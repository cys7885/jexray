package com.jexray.jadx.ui;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Regression coverage for issue #1:
 * {@code NoClassDefFoundError: com/jexray/jadx/apk/LoadedLibrariesModel$UnloadedLibrary} thrown
 * from {@code LoadedLibrariesPanel.labelFor} during {@code updateComponentTreeUI}.
 *
 * <p>Root cause: jadx loads each plugin in its own classloader and reloads plugins in a fresh one
 * when a project is reopened. Jexray's Native View dialog (which hosts the Loaded Libraries tree)
 * used to survive that reload because {@code JexrayPlugin.unload()} never disposed it. When a later
 * theme/settings refresh repainted the stale tree, the renderer's {@code instanceof UnloadedLibrary}
 * lazily loaded that record for the first time -- from the now-closed classloader -- and threw.
 * Its sibling records ({@code ResolvedLibrary}/{@code LoadSite}/{@code UnresolvedCall}) had already
 * been loaded during normal rendering, which is why only {@code UnloadedLibrary} failed.
 *
 * <p>This test models that exact lifecycle with a child-first classloader (the same delegation a
 * jadx plugin loader uses: the plugin's own classes come from the plugin, everything else from the
 * host) and asserts the renderer's guarded entry point, {@code safeLabelFor}, no longer propagates
 * the failure. Against the pre-fix code it fails with the reported {@code NoClassDefFoundError}.
 */
class LoadedLibrariesPanelIssue1RegressionTest {

	private static final String MODEL = "com.jexray.jadx.apk.LoadedLibrariesModel";
	private static final String PANEL = "com.jexray.jadx.ui.LoadedLibrariesPanel";

	@Test
	void rendererSurvivesRepaintAfterPluginClassloaderClosed() throws Exception {
		PluginClassLoader plugin = new PluginClassLoader(
				Paths.get("target", "classes"),
				getClass().getClassLoader());

		// Panel fully initialised while the loader is open, as during normal use.
		Class<?> panel = Class.forName(PANEL, true, plugin);

		// The sibling records ARE loaded when resolved/unresolved rows render...
		Class.forName(MODEL + "$ResolvedLibrary", true, plugin);
		Class.forName(MODEL + "$LoadSite", true, plugin);
		Class.forName(MODEL + "$UnresolvedCall", true, plugin);
		// ...but $UnloadedLibrary is only touched when an Unloaded node is actually painted -- the
		// stale panel in the bug never painted one before the reload, so it stays unloaded here.
		assertFalse(plugin.hasLoaded(MODEL + "$UnloadedLibrary"),
				"precondition: UnloadedLibrary must not be loaded before the classloader closes");

		Method safeLabelFor = panel.getDeclaredMethod("safeLabelFor", Object.class);
		safeLabelFor.setAccessible(true);

		// jadx reopens the project -> the old plugin classloader is closed while the panel lingers.
		plugin.markClosed();

		// A theme/settings refresh repaints the stale tree: the renderer reaches the
		// `instanceof UnloadedLibrary` check and tries to load that record for the first time.
		try {
			Object label = safeLabelFor.invoke(null, new Object());
			assertNull(label, "a non-matching node renders with its default label (null)");
		} catch (InvocationTargetException e) {
			if (e.getCause() instanceof NoClassDefFoundError) {
				fail("issue #1 regression: renderer propagated " + e.getCause()
						+ " from a stale panel after the plugin classloader closed");
			}
			throw e;
		}
	}

	/**
	 * Mirrors jadx's plugin classloader: the plugin's own {@code com.jexray.*} classes are served
	 * from the plugin (child-first, so they do not leak in from the test classpath), everything else
	 * (jadx api, Swing, gson, fife) is delegated to the parent. Once {@link #markClosed()} is
	 * called, a first-time load of a plugin class fails exactly as a closed {@code URLClassLoader}
	 * would -- reproducing the reported {@code ClassNotFoundException} cause without depending on
	 * jar-vs-directory {@code close()} semantics.
	 */
	private static final class PluginClassLoader extends ClassLoader {
		private final Path classesDir;
		private volatile boolean closed;

		PluginClassLoader(Path classesDir, ClassLoader parent) {
			super("jexray-plugin", parent);
			this.classesDir = classesDir;
		}

		void markClosed() {
			this.closed = true;
		}

		boolean hasLoaded(String name) {
			return findLoadedClass(name) != null;
		}

		@Override
		protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
			if (!name.startsWith("com.jexray.")) {
				return super.loadClass(name, resolve); // host-provided: jadx, swing, gson, fife
			}
			synchronized (getClassLoadingLock(name)) {
				Class<?> c = findLoadedClass(name);
				if (c == null) {
					c = findClass(name);
				}
				if (resolve) {
					resolveClass(c);
				}
				return c;
			}
		}

		@Override
		protected Class<?> findClass(String name) throws ClassNotFoundException {
			if (closed) {
				throw new ClassNotFoundException(name + " (plugin classloader closed)");
			}
			Path file = classesDir.resolve(name.replace('.', '/') + ".class");
			if (!Files.isRegularFile(file)) {
				throw new ClassNotFoundException(name);
			}
			try {
				byte[] bytes = Files.readAllBytes(file);
				return defineClass(name, bytes, 0, bytes.length);
			} catch (Exception e) {
				throw new ClassNotFoundException(name, e);
			}
		}
	}
}
