{
  "targets": [{
  "target_name" : "gpgme",
  "sources":["gpgme.cpp"],
  "cflags!": [ "-fno-exceptions"],
    "cflags_cc!": [ "-fno-exceptions" ],
    "conditions": [
            ["OS=='mac'", {
              "xcode_settings": {
                "GCC_ENABLE_CPP_EXCEPTIONS": "YES"
              },
               "link_settings": {
                "libraries": [
                    "/usr//local/lib/libgpgme.dylib"
                ]
            }

            }],
            ["OS=='linux'", {
               "link_settings": {
                "libraries": [
                    "/usr/local/lib/libgpgme.so"
                ]
            }
            }]
            
          ]
  
  }]
}