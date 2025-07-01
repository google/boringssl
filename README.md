# Deprecated Branch

The `chromium-stable-with-bazel` branch is no longer being updated.
Historically, this branch pointed to, though lagged behind, the revision of
BoringSSL that the current latest stable release of Chromium used. It was used
by projects that wanted some slower-moving branch to follow than `HEAD`.

BoringSSL now tags periodic releases that can be used instead. See the tags of
the form `0.YYYYMMDD.N`. These releases contain Bazel builds.
