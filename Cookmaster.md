Cookmaster 1
============

Cookmaster was a cryptography-reverse chellenge in which we were tasked to steal the secret sauce from an automatic sauce maker. The challenges provides us with a zip file and a link to a web interface.

The zip file contained an `interface` directory, a `cookmaster-bin` directory, dockerfiles to set it up and a script to compute an access token.

Two files, `flag1` and `flag2` were present in `controller-bin` and contained mock flags. `controller-bin` contained two directories, `controller` and `heater`, both containing a Dockerfile. `flag1` is copied to controller docker container, flag2 is copied in heater's one. Let's focus on controller and on the interface.

The interface was a lengthy python script along with templates and scripts.
The scripts being named `create_canbus.sh` and `create_canbridge.sh`, it can be inferred that the interface will receive orders which will then be dispatched on a CAN (or CAN-like) bus to controller and heater services.

The web interface opened a websocket to the server. A more convenient route `/debug` was available to monitor everything the server would send us, but Developer Tools can do the same thing.
Buttons were shown on the web interface, which upon clicked would send to the server `sauce:Pomodoro` or `sauce:Pepper Sauce`.
The websocket interface was available as a global Javascript variable so that executing `ws.send('sauce:Pomodoro')` would do the same thing as clicking on the button.

The controller container contained a single disgusting 9MB Rust binary with symbols included and a `recipes.json` which contained the recipes for Pomodoro and Pepper Sauce.
After navigating randomly with IDA in the binary, the string "secret sauce" can be found in a code which compares it to another string.

Sending the server `sauce:secret sauce` was enough to have send the flag : `potluck{uns3cur3_n0nc35_4r3_n0t_th3_s3cr3t_s4uc3}`.
I still do not know what nonce the flag is referring to.
