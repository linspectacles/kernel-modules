<p align="center">
  <a href="https://github.com/brunonlinespace/brunonlinespace/blob/main/linspectacles/kernel-modules.png">
    <img
      src="https://raw.githubusercontent.com/brunonlinespace/brunonlinespace/main/linspectacles/kernel-modules.png"
      alt="Kernel Modules screenshot"
      width="900"
    >
  </a>
</p>

# Kernel Modules

**Expose. Explore. Explain.**

Kernel Modules is a read-only inspector for loaded Linux kernel modules, combining the runtime module list with static `modinfo` metadata, sysfs runtime state, taint context and selected-module symbol lookup.

Current release: **1.0.7**

Repository: <https://github.com/linspectacles/kernel-modules>

## What Kernel Modules is

Kernel Modules answers a focused question: **which modules are loaded, what metadata and relationships do they report, and what runtime state is exposed for the selected module?**

It keeps acquisition and interpretation close to the Linux interfaces actually used by the applet. When a source is unavailable, restricted, or does not report a field, the README does not imply that the applet can manufacture the missing information.

## Highlights

- Loaded-module inventory from `/proc/modules` including reported size, use count, state and **Used By** relationships.
- Static module metadata, aliases, declared dependencies and module file information from `modinfo`.
- Runtime refcount, parameters, holders and module taint markers from `/sys/module/<module>/...`.
- Selected-module **Symbols...** lookup through `/proc/kallsyms`.
- Global kernel taint value from `/proc/sys/kernel/tainted` shown as running-kernel context rather than falsely attributed to one module.
- Search/category filtering and persistent Metadata Details presentation.

## Data sources and acquisition

- `/proc/modules`.
- `modinfo`.
- `/sys/module/<module>/...`.
- `/proc/kallsyms` for explicit selected-module symbol lookup.
- `/proc/sys/kernel/tainted`.

The applet uses those sources according to the acquisition paths implemented in this release. Optional tools or privileged helpers only affect the views/actions that explicitly use them; they are not treated as silent substitutes for unrelated sources.

## Interface

Kernel Modules follows the LinSpectacles inventory + **Metadata Details** pattern where applicable: an acquired inventory remains separate from the details for the selected record, and search/filter controls operate on the data the applet has actually collected.

The applet's **Options** surface provides the presentation/source/about controls implemented by this release, together with export controls where present in the source. Applet-specific actions remain explicit rather than being folded into background collection.

## Read-only and scope boundaries

Kernel Modules inventories loaded runtime modules, not every component built into the kernel. It does not load/unload modules, write module parameters or change module state. Declared `modinfo` dependencies and current sysfs holder relationships are reported separately.

## Useful keyboard shortcuts

| Command | Shortcut |
| --- | --- |
| Show / hide Metadata Details | `F3` |
| Toggle Horizontal / Vertical details | `Ctrl+L` |
| Refresh | `Shift+F5` |
| Symbols | `F4` |
| Options | `Ctrl+/` |

## Running from source

The supplied source is directly runnable on Linux. The Python-side requirements are:

- Python 3.
- PyQt6 for the graphical interface.

Create a local virtual environment if you do not already have the required Python packages in the environment you want to use:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install PyQt6
python3 linspectacles_kernel_modules/standalone.py
```

Linux commands, procfs/sysfs interfaces, system services, or optional helpers mentioned in **Data sources and acquisition** are applet-specific runtime inputs. A missing optional source is handled by the applet's existing availability/error path; it is not replaced here with an invented dependency or capability.

No RPM installation instructions are included in this README.

## Source layout and LinSpectacles integration

The applet source is contained in:

```text
linspectacles_kernel_modules/
├── __init__.py
├── applet.json
├── standalone.py
├── README.md
├── LICENSE
└── kernel_modules/
    ├── __init__.py
    ├── applet.py
    ├── _support.py
    └── icon.png
```

`applet.json` supplies the LinSpectacles applet identity and entrypoint metadata. `standalone.py` launches the applet directly, while the package's applet factory provides the host-loadable LinSpectacles integration used by the source.

## Configuration

Presentation and inspection preferences are persisted only through the settings mechanisms already implemented by the applet. Persisted UI state does not grant the applet permission to modify the inspected Linux subsystem.

## Scope

Kernel Modules is intentionally specialist. Related Linux information that belongs to another LinSpectacles subsystem remains outside this applet rather than being inferred or duplicated here.

## License

GNU General Public License v3.0 or later. See [`LICENSE`](LICENSE).

## Links

- LinSpectacles organisation: <https://github.com/linspectacles/>
- Repository: <https://github.com/linspectacles/kernel-modules>
- Issues: <https://github.com/linspectacles/kernel-modules/issues>

<p align="center">
  <a href="https://github.com/linspectacles/kernel-modules">
    <img
      src="kernel_modules/icon.png"
      alt="Kernel Modules"
      width="256"
    >
  </a>
</p>
