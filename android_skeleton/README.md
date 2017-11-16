This document describes how to setup the Android AppAuth APP [``mod_auth_openidc``](https://github.com/pingidentity/mod_auth_openidc).

# Prerequisites
* Android Studio 3.0

# Get AppAuth code
```
git clone https://github.com/openid/AppAuth-Android.git
```

# Setting up Android Studio
1. Download Android Studio from https://developer.android.com/studio/index.html
1. Follow the instructions from https://developer.android.com/studio/install.html
1. Execute Android Studio
1. Choose `Open existing project` and select the AppAuth root folder
1. Install all the required dependencies as requested by the IDE (there will be many)
1. Run the application. Two options:
    1. With your physical device
        * No major problems are expected with this one.
    1. With a virtual device.
        1. Download the image for x86_64, as it will be accelerated.
        1. Choose a medium resolution device, that will be faster.
        1. Select hardware graphics acceleration.

# App configuration
1. Check https://github.com/openid/AppAuth-Android/tree/0.7.0/app for
    instructions on how to tune the configuration file to connect with an OP.
    No code changes are required for this one.
1. Check https://github.com/openid/AppAuth-Android for advanced instructions
    if you want to change App behaviour (such as using a Client password,
    or a flow different than `CODE`. These might require non-trivial
    changes to the code.