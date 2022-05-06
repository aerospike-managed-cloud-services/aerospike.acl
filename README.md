# aerospike.acl

Aerospike DB user and role management with asadm

## Installation

Ansible knows where to look for collections based on the `collections_paths` variable set in your `ansible.cfg` file, for example:

```ini
[defaults]
collections_paths=~/ansible/collections
```

Collections _must_ be installed to one of the directories listed in `collections_paths` for ansible to be able to find them.

### From a release artifact

Download the collection archive for the specific release you need under [releases](https://github.com/aerospike-managed-cloud-services/aerospike.acl/releases).

```shell
$ ansible-galaxy collection install {{ path to the downloaded archive }} -p {{ path to your configured collections }}
```

### From a local repo

```shell
$ ansible-galaxy collection install {{ path to the collection repo }} -p {{ path to your configured collections }}
```

---

## Development

Ansible tools expect that the collection you're working in is in a directory under `ansible/collections/ansible_collections`, this is a hard requirement due to how ansible structures import paths for modules.

Additionally collection repositories have the name `{{ namespace }}.{{ collection }}` (for example this repo is `aerospike.acl`), however the import path requires that we do `{{ namespace }}/{{ acl }}`.

Which means that we need to set up the repository like this:

```shell
mkdir -p ~/repos/dev/ansible/collections/ansible_collections/aerospike
cd ~/repos/dev/ansible/collections/ansible_collections/aerospike
git clone git@github.com:aerospike-managed-cloud-services/aerospike.acl.git acl
```

Note that the path you select needs to be included in your `collection_paths` for the integration tests to work, for example with the repo setup as above we'd need the following:

```ini
[defaults]
collections_paths=/home/username/repos/dev/ansible/collections
```

### Unit Tests

Unit tests can be run with the `make test` directive, this both sets up a python virtualenv and runs `pytest`.

Because of the ansible module path requirements we have to set the `PYTHONPATH` variable to include the parent directories, this is done for us in the pytest config file here:

```ini
[pytest]
pythonpath = "../../../"
```

### Integration testing

With Docker we can spin up a local Aerospike and then run actual end-to-end tests in ways:

1. Running a playbook with tasks referencing our modules
1. Calling the python modules directly with json data as input

Both of the above require the following:

1. A local Aerospike which can be spun up with `make start-aerospike` (assuming you have Docker installed)
1. The `asadm` executable in your shell path
1. The `PYTHONPATH` variable in your shell must contain `../../../`

### Run a local Aerospike with Docker

We can run a local Aerospike using docker, however we have to run the enterprise edition in order to have access to the security features, this means we need to supply a feature key and a custom Aerospike configuration.

The custom Aerospike configuration is already setup in `./test_config/aerospike.conf`, we just need to add a valid feature key at `./test_config/features.conf`. At runtime the `test_config` directory gets mounted by Docker at `/opt/etc/aerospike` making both the `aerospike.conf` file and the `features.conf` file available to the asd process.

The makefile is setup with the following directives:

- `make start-aerospike`
- `make stop-aerospike`

### Install asadm

Follow the build and install directions for asadm here: https://github.com/aerospike/aerospike-admin

Once you've built an executable you'll need to add it to your path, similar to this:

```shell
ln -s ~/repos/aerospike-admin/build/bin/asadm ~/.local/bin/asadm
```

Once installed (and Aerospike is running) you should be able to list users like this using asadm:

```shell
asadm --config-file="test_config/astools.conf" -U admin -P admin --instance="test" -e 'show users' --json | sed -n '/^{$/,$p' | jq '.'
{
  "title": "Users (2022-05-06 20:38:20 UTC)",
  "groups": [
    {
      "records": [
        {
          "User": {
            "raw": "admin",
            "converted": "admin"
          },
          "Roles": {
            "raw": [
              "user-admin"
            ],
            "converted": "user-admin"
          },
          "Connections": {
            "raw": "3",
            "converted": "3"
          }
        }
      ]
    }
  ]
}
```

### Run a module directly with test data

Probably the quickest way to develop module features is to just run the module directly with python specifying the desired input.

For example in `test_config` we have both `args-users.json` and `args-roles.json` these can be run with the corresponding modules paths like:

```shell
python -m plugins.modules.users test_config/args-users.json | jq '.'
{
  "changed": true,
  "failed": false,
  "original_message": "",
  "message": "Created user foo with roles write",
  "invocation": {
    "module_args": {
      "asadm_config": "test_config/astools.conf",
      "user": "foo",
      "password": "bar",
      "roles": [
        "write"
      ],
      "state": "present",
      "asadm_cluster": "test",
      "asadm_user": "admin",
      "asadm_password": "admin"
    }
  },
  "warnings": [
    "Module did not set no_log for password",
    "Module did not set no_log for asadm_password"
  ]
}
```

Note that again you need to set the `PYTHONPATH` to include `../../../` for the above to work.

### Use ansible-play to run modules

Of course we can also run the modules as tasks directly with ansible as well, in the `test_confg` directory there's a play that exercises both roles and users, it can be run as follows:

```shell
ansible-playbook test_config/test_play.yml

PLAY [test managing users and roles] *****************************************************************************
TASK [Gathering Facts] *******************************************************************************************

TASK [Create/Update roles] ***************************************************************************************
ok: [localhost] => (item={'name': 't2-role', 'state': 'absent', 'privs': ['read']})
changed: [localhost] => (item={'name': 't6', 'state': 'present', 'privs': ['write']})

TASK [Create/Update users] ***************************************************************************************
changed: [localhost] => (item={'name': 't2', 'state': 'present', 'password': 'bar', 'roles': ['t2-role']})

PLAY RECAP *******************************************************************************************************
localhost                  : ok=3    changed=2    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```

## Maintainer section: releasing

To cut a release of this software, automated tests must pass. Check under `Actions` for the latest commit.

_Don't forget_ to update the version in the `galaxy.yml` file, failure to do this will result in build artifacts with incorrect versions.

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
