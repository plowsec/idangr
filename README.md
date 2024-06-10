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

# Usage

Right-click within Hex-Rays and select "Build call state". This will create an angr call state and automatically define symbolic variables for every parameter of the function. Then you can use it in the Python console like this:

```
>>> globals.state
<BV64 0x1c00109e8>
```
# Hot-reload

Well almost. If you edit the code's extension, you won't need to restart IDA for the changes to take effect. This is really important to add SimProcedure and use them directly, or customize angr's exploration.

# Roadmap

* GUI to set find/avoid addresses and explore
* Coverage
* Static analysis
