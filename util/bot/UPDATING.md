# Updating Bot Dependencies

This directory consumes tools from other repositories for use on CI/CQ bots.

## Local Testing

For a similarly-configured local checkout for testing, run:

```sh
mkdir boringssl-gclient
cd boringssl-gclient
gclient config --unmanaged --deps-file=util/bot/DEPS https://boringssl.googlesource.com/boringssl/
gclient sync
```

Optional `checkout_*` variables in [DEPS](./DEPS) can be enabled via `gclient`
[`custom_vars`](https://www.chromium.org/developers/how-tos/depottools/#gclient-file).

## Updating Revisions

* **[DEPS](./DEPS)**: Update the variables as described in the inline comments.

* **`.sha1` files**: These correspond to files downloaded from Google Cloud
  Storage. To update, place the updated files in their intended location, update
  the current revision noted below in this file, and run:

  ```sh
  upload_to_google_storage.py -b chromium-tools FILE
  ```

  * **`nasm-win32.exe`**: Update to the appropriate release of NASM, found at
    https://www.nasm.us/. Use the same version as Chromium, found in Chromium's
    [README.chromium](https://chromium.googlesource.com/chromium/deps/nasm/+/refs/heads/main/README.chromium).
    Extract `nasm.exe` from the download named `nasm-VERSION-win64.zip`.

    The current revision is **`nasm-3.01-win64.zip`**.

  * **`sde-linux64.tar.xz` and `sde-win32.tar.xz`**: Download the latest release
    from Intel at
    https://software.intel.com/en-us/articles/intel-software-development-emulator,
    and upload it with the following command (note the bucket is different):

    ```sh
    upload_to_google_storage.py -b chrome-boringssl-sde sde-linux64.tar.xz sde-win32.tar.xz
    ```

    The current revision is **`sde-external-10.13.1-2026-07-28-*.tar.xz`**.

When adding new files, remember to update [.gitignore](../../.gitignore).
