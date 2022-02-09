## Taikari
Taikari is intent on **destroying** the Arcaea world.

## Hack Tool Sets
| name | description |
| :--- | :---------- |
| captureSSL     | Capture the SSL traffic print to screen |
| dumpCertficate | Hex dump the latest P12 certificate |
| hookOnlineManagerCtor | An almost perfect hook scheme of OnlineManager. |
| challengeHookTest | Test the challenge hook |
| challengeServer | Challenge server over the HTTP |
| pretendArcVersion | Set the fake arcaea version |
| pretendDeviceId | Set the fake device id |

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
|  Arcaea (build) |  Architecture      |
| :-------------- | :----------------- |
| 3.11.2c_1019305 | arm64-v8a          |
| 3.11.2c_1019305 | armeabi-v7a        |


## License
Licensed under `616 SB License`.
