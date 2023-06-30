#!/bin/bash

openssl genrsa -out keypair.pem 2048

openssl rsa -in keypair.pem -pubout > key.pub