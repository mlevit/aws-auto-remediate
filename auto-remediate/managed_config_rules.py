import boto3
import datetime
import json
import logging
import os
import sys
import tempfile
import threading


class ManagedConfigRules:
    def __init__(self, logging):
        self.logging = logging
    
    
    def access_keys_rotated(self, record):
        """
        Deletes IAM User's access and secret key
        """
        pass
    

    def restricted_ssh(self, record):
        """
        Deletes inbound rules within Security Groyps that match:
            Protocal: TCP
            Port: 22
            Source: 0.0.0.0/0 or ::/0
        """
        pass