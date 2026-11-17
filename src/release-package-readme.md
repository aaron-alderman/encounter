# Encounter Linux release

This archive contains the Rust executable and compiled application images.
The image names and their SHA-256 pins are listed in release.rel. Image
serving requires a compatible x86-64 GNU/Linux host with the system C
runtime, libsqlite3.so.0, libpq.so.5, libcurl.so.4, libssl.so.3, libcrypto.so.3,
and libsystemd.so.0 (with the sd-bus method timeout API).

Verify the archive with the separately supplied SHA-256 before extraction.
From the extracted directory, choose an application and an external store:

```bash
app=workgarden
pin=$(awk -F'"' -v app="$app" '$2 == app && $4 == "sha256" { print $6 }' release.rel)
bin/encounter serve --image "images/$app.rel" "$pin" /path/to/workgarden-store 24211
```

Use a separate store and port for each application. Keep stores outside
the release directory. For upgrades, stop the old
server and back up the store. Start the new executable with its matching
compiled image and the copied store. Keep the old release and backup
available while verifying the upgrade.
