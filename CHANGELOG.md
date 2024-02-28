# Changelog

## Unreleased

### Changed

- `nkeys` dependency updated to `0.4`

### Changed

-   Don't serialize the permissions map if the allow and deny list are empty ([#2](https://github.com/AircastDev/nats-jwt/issues/2))

## v0.2.0 (2022-07-08)

### Added

-   Add expires field to the jwt claims

### Changed

-   `issued_at` field on the jwt claims is now an i64 to match expires, and the go implementation
-   `nkeys` and `sha2` updated to `0.2` and `0.10` respectively

## v0.1.0 (2021-07-25)

### Added

-   Initial implementation with support for User, and Account JWT creation
