This document describes how to setup the Android  [``AppAuth``](https://github.com/openid/AppAuth-Android) application.

# Prerequisites
* Android Studio 3.0

# Get AppAuth code
```
git clone --branch 0.7.0 https://github.com/openid/AppAuth-Android.git
```

# Setting up Android Studio
1. Download Android Studio from https://developer.android.com/studio/index.html
1. Follow the instructions from https://developer.android.com/studio/install.html
   * Note: The instructions indicate that if you are using Ubuntu 64bit, you should install a series of packages, but the names are wrong. It should say:
```
sudo apt-get install lib32z1 lib32ncurses5 lib32stdc++6
```
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
1. Check https://github.com/openid/AppAuth-Android/blob/0.7.0/app/README.md for
    instructions on how to tune the configuration file to connect with an OP.
    No code changes are required for this one.
1. Check https://github.com/openid/AppAuth-Android/blob/0.7.0/README.md for advanced instructions
    if you want to change App behaviour (such as using a Client password,
    or a flow different than `CODE`. These might require non-trivial
    changes to the code.
