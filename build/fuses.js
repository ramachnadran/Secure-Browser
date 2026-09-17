/**
 * electron-builder afterPack hook — flip Electron's fuses on the packaged binary.
 *
 * Fuses are bits baked into the Electron executable itself. They close escape
 * hatches that no amount of application code can reach, because they are read
 * before our main process starts:
 *
 *   RunAsNode                          `ELECTRON_RUN_AS_NODE=1 ./app` turns the
 *                                      signed binary into a plain Node REPL with
 *                                      full filesystem access. This is the single
 *                                      widest hole in an unfused Electron app.
 *   EnableNodeCliInspectArguments      `--inspect-brk` attaches a debugger to the
 *                                      main process and lets a student call any
 *                                      internal function, including app.exit.
 *   EnableNodeOptionsEnvironmentVariable  NODE_OPTIONS can inject `--require` and
 *                                      run arbitrary code before our first line.
 *   EmbeddedAsarIntegrityValidation    The app archive is hashed and checked at
 *                                      load, so editing app-config.json inside
 *                                      the package stops the app from starting.
 *                                      Only enabled on a SIGNED build: macOS
 *                                      validates the hash against the code
 *                                      signature, so on an ad-hoc signed build
 *                                      every read inside the archive fails and
 *                                      the app opens a blank window.
 *   OnlyLoadAppFromAsar                Refuses a loose `app/` directory beside the
 *                                      archive, which is how the check above is
 *                                      otherwise sidestepped.
 * One fuse is deliberately LEFT AT ITS DEFAULT:
 *
 *   GrantFileProtocolExtraPrivileges   Turning this off would strip file:// of
 *                                      its extra privileges, which sounds right
 *                                      until you remember the launch screen and
 *                                      the quit prompt are loaded with loadFile
 *                                      from inside the archive. Without those
 *                                      privileges the asar path stops resolving
 *                                      and every local page fails to load, so
 *                                      the app opens a blank kiosk window.
 *                                      Verified on a packaged build, not guessed.
 *                                      Closing it properly means serving our own
 *                                      UI from a registered custom scheme instead
 *                                      of file://; until then the exposure is
 *                                      small, because the only file:// pages are
 *                                      two we ship inside the archive and the
 *                                      exam itself loads over https.
 *
 * Integrity validation only takes effect on a signed binary, so this runs
 * before electron-builder signs, and is a no-op worth keeping either way.
 */
const path = require('path');
const { flipFuses, FuseVersion, FuseV1Options } = require('@electron/fuses');

/** The packaged Electron executable, which differs per platform. */
function executablePath(context) {
  const { electronPlatformName, appOutDir, packager } = context;
  const name = packager.appInfo.productFilename;

  if (electronPlatformName === 'darwin') {
    return path.join(appOutDir, `${name}.app`, 'Contents', 'MacOS', name);
  }
  if (electronPlatformName === 'win32') {
    return path.join(appOutDir, `${name}.exe`);
  }
  return path.join(appOutDir, name);
}

/**
 * Integrity validation needs a real signature to check the hash against.
 * electron-builder skips signing when `mac.identity` is explicitly null, and
 * that combination produces an app that packages cleanly and then cannot read
 * its own archive — so the fuse follows whether this build will be signed.
 */
function buildIsSigned(context) {
  if (context.electronPlatformName !== 'darwin') return true;
  if (process.env.CSC_LINK || process.env.CSC_NAME) return true;
  const identity = context.packager.platformSpecificBuildOptions.identity;
  return identity !== null;
}

exports.default = async function flipAppFuses(context) {
  const target = executablePath(context);
  const signed = buildIsSigned(context);
  console.log(`[fuses] hardening ${target}`);
  console.log(
    signed
      ? '[fuses] signed build — archive integrity validation ON'
      : '[fuses] UNSIGNED build — archive integrity validation OFF (needs a signature to verify against)'
  );

  await flipFuses(target, {
    version: FuseVersion.V1,
    resetAdHocDarwinSignature: context.electronPlatformName === 'darwin',

    [FuseV1Options.RunAsNode]: false,
    [FuseV1Options.EnableNodeCliInspectArguments]: false,
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
    [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: signed,
    [FuseV1Options.OnlyLoadAppFromAsar]: true,
    // Cookie encryption is unrelated to lockdown but costs nothing and keeps
    // an exam session token off disk in the clear.
    [FuseV1Options.EnableCookieEncryption]: true
    // GrantFileProtocolExtraPrivileges intentionally omitted — see the note above.
  });

  console.log('[fuses] done');
};
