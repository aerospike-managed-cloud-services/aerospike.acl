> ---
>
> :information_source: How to use this template repository
>
> Ref: [AMS Project Repo] HOWTO document
>
> ### Update and customize the new repo to your needs
>
> 1. Update this README:
>    - update title, description, install steps and anything marked (replace)
>    - add version info to the changelog
>    - Maintainer section might work for you with no changes!
>    - delete this info section from the top
> 1. Read `build-test.yaml` and `release.yaml` (in `.github/workflows`)
>    - update as needed
>    - `release.yaml` and the `makefile` assume you will have a build step,
>      and that your release artifact is a simple tarball
> 1. Read `makefile` and update as needed
>    - Several lines are marked (replace), pay special attention to those
> 1. Create a `dev` branch from `main`
> 1. Create and push a `v0.0` tag to the HEAD of `main`
>
> [ams project repo]: https://aerospike.atlassian.net/wiki/spaces/MS/pages/2567471115/Organization+and+Tooling+AMS+Project+Repo+DRAFT
> [more info]: https://docs.github.com/en/repositories/creating-and-managing-repositories/creating-a-repository-from-a-template
> [aerospike-managed-cloud-services/template-github-repo]: https://github.com/aerospike-managed-cloud-services/template-github-repo
>
> ---

# db-user-management

Aerospike DB user management

## Installation

1. steps to download

1. unpack

1. copy files

---

## Maintainer section: releasing

To cut a release of this software, automated tests must pass. Check under `Actions` for the latest commit.

#### Create an RC branch and test

- We use the Gitflow process. For a release, this means that you should have a v1.2.3-rc branch under your
  dev branch. Like this:

  ```
    main
    └── dev
        └── v1.2.3-rc
  ```

- Update _this file_.

  1. Confirm that the docs make sense for the current release.
  1. Check links!
  1. Update the Changelog section at the bottom.

- Perform whatever tests are necessary.

#### Tag and cut the release with Github Actions

- Once you have tested in this branch, create a tag in the v1.2.3-rc branch:

  ```
  git tag -a -m v1.2.3 v1.2.3
  git push --tags
  ```

- Navigate to ~~github actions URL for this repo~~ and run the action labeled `... release`.

  - You will be asked to choose a branch. Choose your rc branch, e.g. `v1.2.3-rc`

  - If you run this action without creating a tag on v1.2.3-rc first, the action will fail with an error and nothing will happen.

  If you have correctly tagged a commit and chosen the right branch, this will run and create a new release on the [Releases page].

- Edit the release on that page

#### Merge up

- Finish up by merging your `-rc` branch into
  1. `main` and then
  2. `dev`.

## Changelog

<details><summary>(About: Keep-a-Changelog text format)</summary>

The format is based on [Keep a Changelog], and this project adheres to [Semantic
Versioning].

</details>

### versions [x.y.z] (replace)

- with changes listed; you should read [Keep a Changelog]

[Unreleased]: ~~url for ...HEAD~~

[x.y.z]: ~~url for v0.0..x.y.z~~

[0.0]: ~~url for the v0.0 tag~~

[latest release]: ~~url for /releases/latest~~

[Releases page]: ~~url for /releases~~

[keep a changelog]: https://keepachangelog.com/en/1.0.0/
[semantic versioning]: https://semver.org/spec/v2.0.0.html
