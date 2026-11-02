#!/bin/sh
exec cc "$@" -lcurl -lcrypto -lreadline -pthread
