<table>
  <tbody>
  <tr>
    <td style="text-align:left">
      <img src="files/htdoc/favicon.png" width=60>
    </td>
    <td style="text-align:left">
      <h2>Taikari</h2>
      <h4>Taikari is intent on <strong>destroying</strong> the Arcaea world.</h4>
    </td>
  </tr>
  </tbody>
</table>

![ver](https://img.shields.io/badge/taikari-v0.6.2-blue) ![arc](https://img.shields.io/badge/arcaea-4.0.255c-716dba)

## Hack Tool Sets
| name | description |
| :--- | :---------- |
| captureSSL            | Capture the SSL traffic print to screen |
| dumpCertficate        | Hex dump the latest P12 certificate |
| hookOnlineManagerCtor | An almost perfect hook scheme of OnlineManager. |
| challengeHookTest     | Test the challenge hook |
| challengeServer       | Challenge server over the HTTP |
| pretendArcVersion     | Set the fake arcaea version |
| pretendDeviceId       | Set the fake device id |

## Deploy
 - Install frida-server following the official documentation.
 - Copy the `files` folder to `/system/usr/` then renaming to `taikari`.

## Usage
> Recommend to use Frida 15 and Android 7+.
```bash
$ frida -U -f "moe.low.arc" --no-pause -l taikari.js
  # -U (use USB device)
  # -f (spawn the target app)
  # --no-pause (do not pause the thread while app start)
  # -l (load script)
```

## Compatible Info
|  Arcaea (build)   |  arm64-v8a  |  armeabi-v7a  |  x86  |  x86_64  |
| :--------------   | :---------: | :-----------: | :---: | :---:    |
| 3.11.2c_1019305   | ✔           | ✔             | ❌    | ❌      |
| 3.12.0c_1020007   | ✔           | ✔             | ❌    | ❌      |
| 3.12.1c_1020010   | ✔           | ✔             | ❌    | ❌      |
| 3.12.2c_1020517   | ✔           | ✔             | ❌    | ❌      |
| 3.12.6c_1032000   | 🟡          | ❌ (lazy)     | ❌    | ❌      |
| 4.0.0c_1050010    | ❌ (wip)    | 🟡            | ❌    | ❌      |
| 4.0.1c_1050014    | ❌ (wip)    | 🟡            | ❌    | ❌      |
| 4.0.255c_1060002  | ❌ (wip)    | 🟡            | ❌    | ❌      |

## License
Licensed under `616 SB License`.
