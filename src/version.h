// The single place the release version lives. tools\release.ps1 refuses to
// publish if this does not match the version it is asked to release, and the
// updater compares it against the signed manifest (newer wins, never older).
#pragma once
#define NETVIGIL_VERSION "1.0.0"
