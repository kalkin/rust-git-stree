# Git-Stree

Library for working with my improved git subtree schema.

The subtrees with their `<prefix>`, `<repository>` and a target to follow are
tracked in `.gitsubtrees` files. Each `.gitsubtrees` file contains information
about tracked subtrees in the same directory.

## `.gitsubtrees` Format

```ini
[example]
      version = 1 ; opional normally, required if no other key specified
      upstream = https://example.com/ORIGINAL/example
      origin = https://example.com/FORKED/example
      follow = master ; some ref or a semver range
      pre-releases = false ; if allow pulling pre-releases
```
