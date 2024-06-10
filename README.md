IDA Pro extension to work with angr

# Install

Clone this repo in your IDA plugin folder:

Linux:

$HOME/.idapro/plugins

Windows:

%AppData%\Roaming\Hex-Rays\IDA Pro\plugins

## Dependencies

Only `angr` for now. Install it from `pip` for the Python interpreter used by IDA.

Windows:

```
& 'C:\Program Files\Python310\python.exe' -m pip install angr
```

Linux:

```
python3 -m pip install angr
```

# Config

Check `ida_angr_lib/config.json` to set the timeout for angr's analysis.

# Usage

Create `addresses.json` (next to your IDB) and fill it like this:

```json
{
  "find": [
    {
      "address": "0x00000001C0020C5C",
      "description": "Target address to find"
    }
  ],
  "avoid": [
    {
      "address": "0x00000001C0048690",
      "description": "v15 = WinErrorToNtStatus(v3)"
    },
    {
      "address": "addr_buf_zero",
      "description": "0x00000001C0048656 zero address"
    }
  ]
}
```

Right-click within Hex-Rays and select "Build call state". This will create an angr call state and automatically define symbolic variables for every parameter of the function. There is also "Explore from here" that does the same thing AND triggers an angr's exploration (the default one).

Then you can use it in the Python console like this:

```
>>> state
<BV64 0x1c00109e8>
>>> simgr
<SimulationManager with 8 deadended, 4 avoid, 26 timeout (2 errored)>
```

The following globals are available:

* state
* simgr
* proj

# Hot-reload

Well almost. If you edit the code's extension, you won't need to restart IDA for the changes to take effect. This is really important to add SimProcedure and use them directly, or customize angr's exploration.

# Cancellable angr exploration technique

Don't fear to freeze your IDA, you can stop angr's exploration by clicking "Cancel" on the `ida_kernwin.show_wait_box` dialog. Also, a default timeout of 15 minutes is configured in `config.json`.

# Roadmap

* GUI to set find/avoid addresses and explore
* Coverage
* Static analysis
