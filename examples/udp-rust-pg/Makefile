# name of your application
APPLICATION = udp-rust-pg

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1
USEMODULE += sock_udp
USEMODULE += sock_async
USEMODULE += sock_aux_local
USEMODULE += core_thread_flags
USEMODULE += gnrc_udp
USEMODULE += ztimer_msec
USEMODULE += netdev_default
USEMODULE += auto_init_gnrc_netif
# Specify the mandatory networking modules
USEMODULE += gnrc_ipv6_default
# Activate ICMPv6 error messages
USEMODULE += gnrc_icmpv6_error
# Additional networking modules that can be dropped if not needed
USEMODULE += gnrc_icmpv6_echo
# needed for the UDP socket part in the wrappers

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

# The name of crate (as per Cargo.toml package name, but with '-' replaced with '_')
APPLICATION_RUST_MODULE = udp_rust_pg
BASELIBS += $(APPLICATION_RUST_MODULE).module

FEATURES_REQUIRED += rust_target

# Currently unknown, something related to the LED_PORT definition that doesn't
# pass C2Rust's transpilation
BOARD_BLACKLIST := ek-lm4f120xl

include $(RIOTBASE)/Makefile.include
