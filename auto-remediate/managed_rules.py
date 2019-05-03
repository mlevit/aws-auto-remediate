import boto3
import datetime
import json
import logging
import os
import sys
import tempfile
import threading


class ManagedRules:
    def __init__(self, logging, record):
        self.logging = logging
        self.record = record