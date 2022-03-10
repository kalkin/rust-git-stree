//! Library for working with my improved git subtree schema.
//!
//! The subtrees with their `<prefix>`, `<repository>` and a target to follow are tracked in
//! `.gitsubtrees` files. Each `.gitsubtrees` file contains information about tracked subtrees in
//! the same directory.
//!
//! ## `.gitsubtrees` Format
//!
//! ```ini
//! [example]
//!       version = 1 ; opional normally, required if no other key specified
//!       upstream = https://example.com/ORIGINAL/example
//!       origin = https://example.com/FORKED/example
//!       follow = master ; some ref or a semver range
//!       pre-releases = false ; if allow pulling pre-releases
//! ```
use getset::Getters;
use std::collections::HashMap;

use configparser::ini::Ini;
use git_wrapper::ConfigSetError;
use git_wrapper::{
    InvalidRefError, RefSearchError, RepoError, Repository, SubtreeAddError, SubtreePullError,
    SubtreePushError, SubtreeSplitError,
};
use std::path::{Path, PathBuf};

use posix_errors::{PosixError, EAGAIN, EINVAL, ENOENT, ENOTRECOVERABLE, ENOTSUP, EUTF8};

/// Configuration for a subtree
#[derive(Getters, Clone, Debug, Eq, PartialEq)]
pub struct SubtreeConfig {
    /// subtree id
    #[getset(get = "pub")]
    id: String,
    /// Follow schema for subtree
    #[getset(get = "pub")]
    follow: Option<String>,
    /// Origin remote for subtree
    #[getset(get = "pub")]
    origin: Option<String>,
    /// Upstream remote for subtree
    #[getset(get = "pub")]
    upstream: Option<String>,
    /// `true` if this subtree should also pull pre release tags e.g. “1.0.3-23-alpah”
    #[getset(get = "pub")]
    pull_pre_releases: bool,
}

impl SubtreeConfig {
    /// Return a new instance
    #[must_use]
    #[inline]
    pub const fn new(
        id: String,
        follow: Option<String>,
        origin: Option<String>,
        upstream: Option<String>,
        pull_pre_releases: bool,
    ) -> Self {
        Self {
            id,
            follow,
            origin,
            upstream,
            pull_pre_releases,
        }
    }
    /// Return `true` if upstream is set
    #[must_use]
    #[inline]
    pub const fn is_pullable(&self) -> bool {
        self.upstream.is_some()
    }

    /// Return `true` if origin is set
    #[must_use]
    #[inline]
    pub const fn is_pushable(&self) -> bool {
        self.origin.is_some()
    }

    /// Return path to config file
    #[must_use]
    #[inline]
    pub fn config_file(&self) -> String {
        let mut result = self
            .id
            .rsplit_once('/')
            .map_or_else(|| "".to_owned(), |x| x.1.to_owned());
        result.push_str(".gitsubtrees");
        result
    }

    /// Subtree name
    #[must_use]
    #[inline]
    pub fn name(&self) -> String {
        self.id()
            .rsplit_once('/')
            .map_or_else(|| self.id.clone(), |x| x.1.to_owned())
    }

    /// Figure out which named ref to pull from.
    ///
    /// # Panics
    ///
    /// Will panic if `&self` has no upstream remote defined
    ///
    /// # Errors
    ///
    /// Will return a [`PosixError`] when fails to find a ref to pull
    #[inline]
    pub fn ref_to_pull(&self) -> Result<String, PosixError> {
        if !self.is_pullable() {
            panic!("Subtree does not have upstream remote defined");
        }
        let candidate = self.follow.clone().unwrap_or_else(|| "HEAD".to_owned());
        let remote = &self.upstream.clone().unwrap();
        let follow = if candidate == *"@{tags}" {
            find_latest_version(remote)?
        } else if candidate.starts_with("@{") {
            let tmp = candidate
                .strip_suffix('}')
                .unwrap()
                .strip_prefix("@{")
                .unwrap();
            let range = semver::VersionReq::parse(tmp).expect("Got invalid version range");
            return find_latest_version_matching(remote, &range, *self.pull_pre_releases());
        } else if candidate == *"HEAD" {
            git_wrapper::resolve_head(remote)?
        } else {
            candidate
        };
        Ok(follow)
    }
}

/// Aliases some well known urls to their initials.
#[must_use]
#[inline]
pub fn alias_url(url: &str) -> String {
    let github = regex::Regex::new(r"^(git@github.com:|.+://github.com/)").expect("Valid RegEx");
    let gitlab = regex::Regex::new(r"^(git@gitlab.com:|.+://gitlab.com/)").expect("Valid RegEx");
    let bitbucket =
        regex::Regex::new(r"^(git@bitbucket.com:|.+://bitbucket.com/)").expect("Valid RegEx");
    if github.is_match(url) {
        return github.replace(url, "GH:").to_string();
    }
    if gitlab.is_match(url) {
        return gitlab.replace(url, "GL:").to_string();
    }
    if bitbucket.is_match(url) {
        return bitbucket.replace(url, "BB:").to_string();
    }
    url.to_owned()
}

fn versions_from_remote(url: &str) -> Result<HashMap<semver::Version, String>, PosixError> {
    let mut result = HashMap::new();

    let tmp = git_wrapper::tags_from_remote(url)?;
    for s in tmp {
        let version_result = lenient_semver::parse(&s);
        if let Ok(version) = version_result {
            result.insert(version, s);
        }
    }

    Ok(result)
}

/// Return the latest version from remote
///
/// # Errors
///
/// Will return [`PosixError`] if command exits if no versions found.
#[inline]
pub fn find_latest_version(remote: &str) -> Result<String, PosixError> {
    let versions = versions_from_remote(remote)?;
    if versions.is_empty() {
        let message = "Failed to find any valid tags".to_owned();
        return Err(PosixError::new(ENOENT, message));
    }

    let mut keys: Vec<&semver::Version> = Vec::new();
    for v in versions.keys() {
        keys.push(v);
    }
    keys.sort();
    let key = keys.pop().expect("Keys should not be empty");

    Ok(versions.get(key).expect("Keys should exist").clone())
}

/// Return the latest version from remote matching [`semver::VersionReq`]
/// # Errors
///
/// Will return [`PosixError`] if command exits if fails to find matching version.
#[inline]
pub fn find_latest_version_matching(
    remote: &str,
    range: &semver::VersionReq,
    pre_releases: bool,
) -> Result<String, PosixError> {
    let versions_map = versions_from_remote(remote)?;
    let mut keys: Vec<&semver::Version> = Vec::new();
    for v in versions_map.keys() {
        keys.push(v);
    }
    keys.sort();

    let mut latest: Option<&semver::Version> = None;
    let mut versions: Vec<&semver::Version> = versions_map.keys().collect();
    versions.sort();
    for v in versions {
        if range.matches(v) {
            latest.replace(v);
        } else if pre_releases {
            let tmp = semver::Version::new(v.major, v.minor, v.patch);
            if range.matches(&tmp) {
                latest.replace(v);
            }
        } else {
        }
    }
    latest.map_or_else(
        || {
            let msg = format!("Failed to find a tag matching {}", range);
            Err(PosixError::new(ENOENT, msg))
        },
        |v| {
            let result = versions_map.get(v);
            Ok(result.expect("Version is in version map").clone())
        },
    )
}

/// Manages subtrees in a repository
#[derive(Debug)]
pub struct Subtrees {
    repo: Repository,
    configs: Vec<SubtreeConfig>,
}

/// Failed to initialize `Subtrees`
#[allow(missing_docs)]
#[derive(Debug, PartialEq)]
pub enum SubtreesError {
    BareRepo,
    RepoNotFound,
    InvalidConfig(String),
    InvalidDirectory(String),
}

impl From<RepoError> for SubtreesError {
    #[inline]
    fn from(err: RepoError) -> Self {
        match err {
            RepoError::BareRepo => Self::BareRepo,
            RepoError::GitDirNotFound => Self::RepoNotFound,
            RepoError::InvalidDirectory(p) | RepoError::AbsolutionError(p) => {
                let msg = format!("Failed to handle directory {:?}", p);
                Self::InvalidDirectory(msg)
            }
            RepoError::FailAccessCwd => Self::InvalidDirectory("Failed to access CWD".to_owned()),
        }
    }
}

impl From<ConfigError> for SubtreesError {
    #[inline]
    fn from(err: ConfigError) -> Self {
        match err {
            ConfigError::ParseFailed(path_buf) | ConfigError::ReadFailed(path_buf) => {
                Self::InvalidConfig(path_buf.to_string_lossy().to_string())
            }
        }
    }
}

/// Failed reading or parsing a `.gitsubtrees` file.
#[allow(missing_docs)]
#[derive(Debug, PartialEq)]
pub enum ConfigError {
    ReadFailed(PathBuf),
    ParseFailed(PathBuf),
}

/// Failed adding a new subtree to a repository fails
#[allow(missing_docs)]
#[derive(Debug, PartialEq)]
pub enum AdditionError {
    BareRepository,
    WorkTreeDirty,
    InvalidVersion(String),
    WriteConfig(String),
    Failure(String, i32),
}

impl From<AdditionError> for PosixError {
    #[inline]
    fn from(err: AdditionError) -> Self {
        match err {
            AdditionError::BareRepository => {
                let msg = "Operation on bare repository not supported".to_owned();
                Self::new(ENOTSUP, msg)
            }
            AdditionError::WorkTreeDirty => {
                let msg = "Working tree is dirty".to_owned();
                Self::new(ENOTSUP, msg)
            }
            AdditionError::InvalidVersion(version) => {
                let msg = format!("Invalid version {}", version);
                Self::new(EINVAL, msg)
            }
            AdditionError::Failure(msg, _) | AdditionError::WriteConfig(msg) => Self::new(1, msg),
        }
    }
}

impl From<SubtreeAddError> for AdditionError {
    #[inline]
    fn from(err: SubtreeAddError) -> Self {
        match err {
            SubtreeAddError::Failure(msg, code) => Self::Failure(msg, code),
            SubtreeAddError::WorkTreeDirty => Self::WorkTreeDirty,
            SubtreeAddError::BareRepository => Self::BareRepository,
        }
    }
}

impl From<ConfigSetError> for AdditionError {
    #[inline]
    fn from(err: ConfigSetError) -> Self {
        match err {
            ConfigSetError::InvalidConfigFile(f) => {
                let msg = format!("Invalid config file: {}", f);
                Self::WriteConfig(msg)
            }
            ConfigSetError::WriteFailed(f) => {
                let msg = format!("Failed to write config file: {}", f);
                Self::WriteConfig(msg)
            }
            ConfigSetError::InvalidSectionOrKey(msg) => Self::WriteConfig(msg),
        }
    }
}

/// Failed to find specified subtree
#[allow(missing_docs)]
#[derive(Debug, PartialEq)]
pub enum FindError {
    ReadFailed(PathBuf),
    ParseFailed(PathBuf),
    NotFound(String),
}

impl From<ConfigError> for FindError {
    #[inline]
    fn from(err: ConfigError) -> Self {
        match err {
            ConfigError::ReadFailed(p) => Self::ReadFailed(p),
            ConfigError::ParseFailed(p) => Self::ParseFailed(p),
        }
    }
}

/// Failed to update a subtree from remote
#[derive(Debug)]
#[allow(missing_docs)]
pub enum PullError {
    BareRepository,
    Failure(String),
    IOError(std::io::Error),
    InvalidReference,
    NoChanges,
    NoUpstream,
    ReferenceNotFound,
    UTF8Decode(std::string::FromUtf8Error),
    WorkTreeDirty,
}

impl From<PullError> for PosixError {
    #[inline]
    fn from(e: PullError) -> Self {
        match e {
            PullError::BareRepository => {
                let msg = "Can not execute pull operation in bare repository".to_owned();
                Self::new(ENOENT, msg)
            }
            PullError::WorkTreeDirty => {
                let msg = "Can not execute pull operation in a dirty repository".to_owned();
                Self::new(ENOENT, msg)
            }
            PullError::ReferenceNotFound | PullError::InvalidReference => {
                Self::new(EINVAL, "Can not find reference".to_owned())
            }
            PullError::UTF8Decode(_) => {
                let msg = "Failed UTF8 decoding".to_owned();
                Self::new(EUTF8, msg)
            }
            PullError::NoChanges => {
                let msg = "Upstream does not have any new changes".to_owned();
                Self::new(EAGAIN, msg)
            }
            PullError::NoUpstream => {
                let msg = "Subtree does not have a upstream defined".to_owned();
                Self::new(ENOTRECOVERABLE, msg)
            }
            PullError::Failure(msg) => Self::new(1, msg),
            PullError::IOError(err) => Self::from(err),
        }
    }
}

impl From<RefSearchError> for PullError {
    #[inline]
    fn from(prev: RefSearchError) -> Self {
        match prev {
            RefSearchError::ParsingFailure(msg) | RefSearchError::Failure(msg) => {
                Self::Failure(msg)
            }
            RefSearchError::IOError(err) => Self::IOError(err),
            RefSearchError::NotFound(_) => Self::ReferenceNotFound,
        }
    }
}

impl From<InvalidRefError> for PullError {
    #[inline]
    fn from(_prev: InvalidRefError) -> Self {
        Self::InvalidReference
    }
}

impl From<SubtreePullError> for PullError {
    #[inline]
    fn from(prev: SubtreePullError) -> Self {
        match prev {
            SubtreePullError::Failure(msg, _) => Self::Failure(msg),
            SubtreePullError::WorkTreeDirty => Self::WorkTreeDirty,
        }
    }
}

/// Failed to push subtree to remote
#[allow(missing_docs)]
#[derive(Debug)]
pub enum PushError {
    BareRepository,
    NoUpstream,
    Failure(String),
}

impl From<PushError> for PosixError {
    #[inline]
    fn from(err: PushError) -> Self {
        match err {
            PushError::BareRepository => {
                let msg = "Can not execute push operation in bare repository".to_owned();
                Self::new(ENOENT, msg)
            }

            PushError::NoUpstream => {
                let msg = "Subtree does not have a upstream defined".to_owned();
                Self::new(ENOTRECOVERABLE, msg)
            }

            PushError::Failure(msg) => Self::new(1, msg),
        }
    }
}

impl From<SubtreePushError> for PushError {
    #[inline]
    fn from(prev: SubtreePushError) -> Self {
        match prev {
            SubtreePushError::Failure(msg, _) => Self::Failure(msg),
        }
    }
}

/// Failed to split subtree
#[allow(missing_docs)]
#[derive(Debug)]
pub enum SplitError {
    BareRepository,
    WorkTreeDirty,
    Failure(String),
}

impl From<SplitError> for PosixError {
    #[inline]
    fn from(err: SplitError) -> Self {
        match err {
            SplitError::BareRepository => {
                let msg = "Can not execute push operation in bare repository".to_owned();
                Self::new(ENOENT, msg)
            }
            SplitError::WorkTreeDirty => {
                let msg = "Can not execute push operation in a dirty repository".to_owned();
                Self::new(ENOENT, msg)
            }
            SplitError::Failure(msg) => Self::new(1, msg),
        }
    }
}

impl From<SubtreeSplitError> for SplitError {
    #[inline]
    fn from(prev: SubtreeSplitError) -> Self {
        match prev {
            SubtreeSplitError::Failure(msg, _) => Self::Failure(msg),
            SubtreeSplitError::WorkTreeDirty => Self::WorkTreeDirty,
        }
    }
}

#[cfg(not(tarpaulin_include))]
impl std::fmt::Display for ConfigError {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::ParseFailed(p) => {
                let file = p.to_string_lossy();
                write!(f, "Failed to parse file {:?}", file)
            }
            ConfigError::ReadFailed(p) => {
                let file = p.to_string_lossy();
                write!(f, "Failed to read file {:?}", file)
            }
        }
    }
}

#[allow(clippy::missing_errors_doc)]
impl Subtrees {
    /// # Errors
    ///
    /// Throws [`SubtreesError`] if fails to find or access repository.
    #[inline]
    pub fn new() -> Result<Self, SubtreesError> {
        let repo = Repository::default()?;
        let configs = all(&repo)?;
        Ok(Self { repo, configs })
    }

    /// Discover subtrees in a git repository
    #[inline]
    pub fn from_repo(repo: Repository) -> Result<Self, SubtreesError> {
        let configs = all(&repo)?;
        Ok(Self { repo, configs })
    }

    /// Discover subtrees in specified directory
    #[inline]
    pub fn from_dir(path: &Path) -> Result<Self, SubtreesError> {
        let repo = Repository::discover(path)?;
        let configs = all(&repo)?;
        Ok(Self { repo, configs })
    }

    /// # Errors
    ///
    /// Throws errors when there are errors
    ///
    /// # Panics
    ///
    /// Panics when something unexpected happens
    #[inline]
    pub fn add(
        &self,
        subtree: &SubtreeConfig,
        revision: Option<&str>,
        subject: Option<&str>,
    ) -> Result<(), AdditionError> {
        if let Some(rev) = revision {
            let remote = subtree.upstream.as_ref().unwrap();
            let target = subtree.id();

            let title = subject.map_or_else(
                || format!(":{} Import {}", target, alias_url(remote)),
                |v| format!(":{} {}", target, v),
            );
            let msg = format!(
                "{}

git-subtree-origin: {}
git-subtree-remote-ref: {}",
                title, remote, rev
            );
            self.repo.subtree_add(remote, target, rev, &msg)?;
        }
        self.persist(subtree)?;
        let mut cmd = self.repo.git();
        cmd.args(&["add", &subtree.config_file()]);
        let out = cmd.output().expect("Failed to execute git-add(1)");
        if !out.status.success() {
            let msg = String::from_utf8_lossy(&out.stderr).to_string();
            return Err(AdditionError::WriteConfig(msg));
        }

        let mut cmd2 = self.repo.git();
        cmd2.args(&["commit", "--amend", "--no-edit"]);
        let out2 = cmd2.output().expect("Failed to execute git-commit(1)");
        if !out2.status.success() {
            let msg = String::from_utf8_lossy(&out.stderr).to_string();
            return Err(AdditionError::WriteConfig(msg));
        }
        Ok(())
    }

    /// # Errors
    ///
    /// Throws [`ConfigError`] if something goes wrong during parsing
    #[inline]
    pub fn all(&self) -> Result<Vec<SubtreeConfig>, ConfigError> {
        Ok(self.configs.clone())
    }

    /// Returns the repository head commit id
    #[must_use]
    #[inline]
    pub fn head(&self) -> Option<String> {
        Some(self.repo.head())
    }

    fn persist(&self, subtree: &SubtreeConfig) -> Result<(), ConfigSetError> {
        let root = self.repo.work_tree().expect("Repo without work_tree");
        let file = root.join(subtree.config_file());
        let section = subtree.name();
        let mut has_written = false;

        if let Some(value) = subtree.follow() {
            let key = format!("{}.follow", section);
            git_wrapper::config_file_set(&file, &key, value)?;
            has_written = true;
        }

        if let Some(value) = subtree.origin() {
            let key = format!("{}.origin", section);
            git_wrapper::config_file_set(&file, &key, value)?;
            has_written = true;
        }

        if let Some(value) = subtree.upstream() {
            let key = format!("{}.upstream", section);
            git_wrapper::config_file_set(&file, &key, value)?;
            has_written = true;
        }

        if *subtree.pull_pre_releases() {
            let key = format!("{}.pull_pre_releases", section);
            git_wrapper::config_file_set(&file, &key, "true")?;
            has_written = true;
        }

        if !has_written {
            let key = format!("{}.version", section);
            git_wrapper::config_file_set(&file, &key, "1")?;
        }
        Ok(())
    }

    /// Pull remote changes in the specified subtree
    #[inline]
    pub fn pull(&self, subtree: &SubtreeConfig, git_ref: &str) -> Result<String, PullError> {
        let prefix = subtree.id();
        let remote;
        if let Some(url) = subtree.upstream() {
            remote = url;
        } else {
            return Err(PullError::NoUpstream);
        }

        let message = format!("Update :{} to {}", prefix, &git_ref);
        let head_before = self.repo.head();
        self.repo.subtree_pull(remote, prefix, git_ref, &message)?;
        let head_after = self.repo.head();
        if head_before == head_after {
            return Err(PullError::NoChanges);
        }
        let mut cmd = self.repo.git();
        let out = cmd
            .arg("rev-parse")
            .arg("--short")
            .arg("HEAD^2")
            .output()
            .expect("Got second parent");
        if out.status.success() {
            Ok(String::from_utf8(out.stdout)
                .expect("UTF-8 encoding")
                .trim()
                .to_owned())
        } else {
            Err(PullError::Failure(
                "Failed to execute git rev-parse".to_owned(),
            ))
        }
    }

    /// Split changes in a subtree to own artificial history and merge it back into HEAD
    #[inline]
    pub fn split(&self, subtree: &SubtreeConfig) -> Result<(), SplitError> {
        let prefix = subtree.id();
        Ok(self.repo.subtree_split(prefix)?)
    }

    /// Push subtree changes to remote
    #[inline]
    pub fn push(&self, subtree: &SubtreeConfig, git_ref: &str) -> Result<(), PushError> {
        let prefix = subtree.id();
        let remote;
        if let Some(url) = subtree.upstream() {
            remote = url;
        } else {
            return Err(PushError::NoUpstream);
        }

        if git_ref == "HEAD" {
            let head = git_wrapper::resolve_head(remote).expect("asd");
            Ok(self.repo.subtree_push(remote, prefix, &head)?)
        } else {
            Ok(self.repo.subtree_push(remote, prefix, git_ref)?)
        }
    }

    /// List modules with changes since specified git commit id
    #[inline]
    pub fn changed_modules(&self, id: &str) -> Result<Vec<SubtreeConfig>, ConfigError> {
        let subtree_modules = self.all()?;
        if subtree_modules.is_empty() {
            return Ok(vec![]);
        }
        let revision = format!("{}~1..{}", id, id);
        let mut args = vec![
            "diff",
            &revision,
            "--name-only",
            "--no-renames",
            "--no-color",
            "--",
        ];
        for s in &subtree_modules {
            args.push(&s.id);
        }
        let proc = self
            .repo
            .git()
            .args(args)
            .output()
            .expect("Failed running git diff");
        if !proc.status.success() {
            return Ok(vec![]);
        }

        let mut result = Vec::new();
        let text = String::from_utf8_lossy(&proc.stdout);
        let changed: Vec<&str> = text.lines().collect();
        for f in &changed {
            for d in subtree_modules.iter().rev() {
                if f.starts_with(d.id.as_str()) {
                    result.push(d.clone());
                    break;
                }
            }
        }

        result.dedup();
        Ok(result)
    }

    /// Find subtree by name
    #[allow(clippy::missing_panics_doc)]
    #[inline]
    pub fn find_subtree(&self, needle: &str) -> Result<SubtreeConfig, FindError> {
        let configs = self.all()?;
        for c in configs {
            if c.id() == needle {
                return Ok(c);
            }
        }
        Err(FindError::NotFound(needle.to_owned()))
    }
}

fn configs_from_path(
    repo: &Repository,
    parser: &mut Ini,
    path: &Path,
) -> Result<Vec<SubtreeConfig>, ConfigError> {
    let content;
    match repo.hack_read_file(path) {
        Err(_) => return Err(ConfigError::ReadFailed(path.to_path_buf())),
        Ok(vec) => {
            content = String::from_utf8_lossy(&vec).to_string();
        }
    }
    let msg = &format!("Failed to parse {:?}", path);
    let config_map = parser.read(content).expect(msg);
    let parent_dir = path.parent();
    let mut result = Vec::with_capacity(config_map.keys().len());
    for name in config_map.keys() {
        let id: String;
        if let Some(parent) = parent_dir {
            id = parent
                .join(name)
                .to_str()
                .expect("Convertable to str")
                .to_owned();
        } else {
            id = name.clone();
        }
        result.push(SubtreeConfig {
            id,
            follow: parser.get(name, "follow"),
            origin: parser.get(name, "origin"),
            upstream: parser.get(name, "upstream"),
            pull_pre_releases: parser
                .getbool(name, "pull-pre-releases")
                .unwrap_or_default()
                .unwrap_or(false),
        });
    }
    Ok(result)
}

fn config_files(repo: &Repository) -> Vec<PathBuf> {
    let mut cmd = repo.git();
    cmd.arg("ls-files").args(&[
        "-z",
        "--cached",
        "--deleted",
        "--",
        ".gitsubtrees",
        "**/.gitsubtrees",
    ]);
    let out = cmd.output().expect("Successful git-ls-files(1) invocation");
    let tmp = String::from_utf8(out.stdout).expect("UTF-8 encoding");
    let files: Vec<&str> = tmp.split('\0').filter(|e| !e.is_empty()).collect();
    let mut result: Vec<PathBuf> = Vec::with_capacity(files.len());
    for line in files {
        result.push(PathBuf::from(line));
    }

    result
}

fn all(repo: &Repository) -> Result<Vec<SubtreeConfig>, ConfigError> {
    let config_paths = config_files(repo);
    let mut result = vec![];
    let mut config_parser = Ini::new_cs();
    for path in config_paths {
        let mut tmp = configs_from_path(repo, &mut config_parser, &path)?;
        result.append(&mut tmp);
    }

    Ok(result)
}

#[cfg(test)]
mod test {
    use crate::SubtreeConfig;
    use crate::Subtrees;
    use git_wrapper::Repository;

    use tempfile::TempDir;

    #[test]
    fn bkg_monorepo() {
        let subtrees = Subtrees::new().unwrap();
        {
            let result = subtrees.all();
            assert!(result.is_ok(), "Found subtree configs");
            let all_configs = result.unwrap();
            assert!(all_configs.len() > 100, "Sould find at least 100 subtrees");
        }

        // TODO rewrite it as a test for
        {
            let expected = "rust/git-wrapper";
            let result = subtrees.find_subtree(expected);
            assert!(result.is_ok(), "Found subtree rust/git-wrapper subtree");
            let gsi_subtree = result.unwrap();
            let actual = gsi_subtree.id();
            assert!(
                actual == expected,
                "Expected subtree id {}, got {}",
                expected,
                actual
            );
        }
    }

    /*#[test]
    fn initialization() {
        let tmp_dir = TempDir::new().unwrap();
        let repo_path = tmp_dir.path();
        let _ = BareRepository::create(repo_path).expect("Created bare repository");
        let actual = Subtrees::from_dir(&repo_path);
        assert!(actual.is_ok(), "Expected a subtrees instance");
    }*/

    #[test]
    fn subtree_add() {
        let tmp_dir = TempDir::new().unwrap();
        let repo_path = tmp_dir.path();
        {
            let repo = Repository::create(repo_path).unwrap();
            let readme = repo_path.join("README.md");
            std::fs::File::create(&readme).unwrap();
            std::fs::write(&readme, "# README").unwrap();
            repo.stage(&readme).unwrap();
            repo.commit("Test").unwrap();
        }
        let mgr = Subtrees::from_dir(&repo_path).unwrap();
        let config = SubtreeConfig {
            id: "bar".to_string(),
            follow: Some("master".to_string()),
            origin: None,
            upstream: Some("https://github.com/kalkin/file-expert".to_string()),
            pull_pre_releases: false,
        };
        let actual = mgr.add(&config, Some("master"), None);
        assert!(actual.is_ok(), "Expected a subtrees instance");
    }

    #[test]
    fn subtree_pull() {
        let tmp_dir = TempDir::new().unwrap();
        let repo_path = tmp_dir.path();
        {
            let repo = Repository::create(repo_path).unwrap();
            let readme = repo_path.join("README.md");
            std::fs::File::create(&readme).unwrap();
            std::fs::write(&readme, "# README").unwrap();
            repo.stage(&readme).unwrap();
            repo.commit("Test").unwrap();
        }
        let mgr = Subtrees::from_dir(&repo_path).unwrap();
        let config = SubtreeConfig {
            id: "bar".to_string(),
            follow: Some("v0.10.1".to_string()),
            origin: None,
            upstream: Some("https://github.com/kalkin/file-expert".to_string()),
            pull_pre_releases: false,
        };
        mgr.add(&config, Some("v0.10.1"), None).unwrap();
        let actual = mgr.pull(&config, "v0.13.1");
        assert!(
            actual.is_ok(),
            "Expected successful pull execution, got: {:?}",
            actual
        );
    }
}
