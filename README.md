# Assignment instructions
Download this repository as a [zip file](https://github.com/alejandro-perez/openid_course/archive/master.zip) or clone it from:
```
git clone https://github.com/alejandro-perez/openid_course.git
```

Choose one of the following assignments and follow the linked instructions:

1. Implement a Relying Party in Python: [instructions](python_skeleton/README.md)
1. Implement a Relying Party in Java: [instructions](java_skeleton/README.md)
1. Use the Apache module ``mod_auth_openidc`` as a black-box Relying Party: [instructions](apache_skeleton/README.md)
1. Use the Android application `AppAuth` as a black-box Relying Party: [instructions](android_skeleton/README.md)
 
After completing the assignments, experiment with your setup by applying the
suggested tweaks in [OpenID Connect Parameter options](parameter_exercises.md). 

All OpenID Connect specifications can be found at http://openid.net/developers/specs/.

# Provider information

A custom OpenID Connect Provider with the issuer URI `https://op1.test.inacademia.org` can be used to test your Relying
Party against.

Static client registration can be performed through the web interface at `https://op1.test.inacademia.org/client_registration/`.

It has the following username-password pairs configured:
```
diana - krall
babs - howes
upper - crust
```

# Development environment recommendations
The assignments can be performed in any environment of your preference, as long as the requirements described for each one are met. However, we are certain that all the software can be executed on a Ubuntu Xenial (16.04) LTS 64bit.

The use of the recommended IDEs (pyCharm, IntelliJ, and Android Studio) requires a considerable amount of RAM. Hence, if you plan to implement the exercises in a VM, make sure you allocate enough memory for them to run or use lighter alternatives (e.g. sublime text, notepad++...).

