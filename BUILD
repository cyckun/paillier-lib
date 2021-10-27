cc_binary(
    name = "paillier_test",
    srcs = [
        "paillier_test.cc",
	"paillier_lib.cc",
	"paillier.h",
    ],
    copts = [
        "-std=c++17",
    ],
    deps = [
	"@boringssl//:crypto",
    ]
)

cc_library(
    name = "paillier-lib",
    srcs = [
        "paillier_lib.cc",
    ],
    hdrs = [
        "paillier.h",
    ],
    copts = [
        "-fPIC",
        "-std=c++17",
        "-DMOCK",
    ],
    deps = [
        "@boringssl//:crypto",
    ],
)


