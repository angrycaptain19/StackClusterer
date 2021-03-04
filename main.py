"""
Author : Zipiao Wan
Email  : wanzipiao@bytedance.com
Date   : 3.4.2021
Version: alpha 0.0.1
Usage  : Convert json styled fd_leak upload log into mapping clustered by stack-trace and count.
Powered by C&C
"""
import os
import json
from utils import *
import heapq
import pprint

class FdClusterer(object):
    """
        Class that provides utilities for converting .log file to a python dictionary
        or correlated json output
    """
    def __init__(self, path):
        self._file_path = path
        self._cluster_mapping = dict()
        self._stack_hash_mapping = dict()
        self._json_instance = None
        self._leak_log_header = None
        self.__init_json()

    def __init_json(self):
        if not os.path.exists(self._file_path):
            raise RuntimeError(INVALID_LOG_PATH + self._file_path)
        try:
            with open(self._file_path) as json_raw_file:
                self._json_instance = json.load(json_raw_file)
        except:
            raise RuntimeError(PARSE_JSON_FAILED + self._file_path)
        self.__process_stack()

    def __process_stack(self):
        if not self._json_instance or not len(self._json_instance):
            raise RuntimeError(EMPTY_JSON_INSTANCE)
        for (i, json_obj) in enumerate(self._json_instance):
            # Header
            if not i:
                self._leak_log_header = json_obj
            # Last system attribute, ignore
            elif i == len(self._json_instance) - 1:
                break
            # Actual Stack Trace Instance
            else:
                try:
                    raw_stack = json_obj["data"].strip()
                    start_idx = raw_stack.find("\n")
                    index = -1 if start_idx == -1 else start_idx
                    valid_stack = raw_stack[index+1 : ]
                    hash_code = hash(valid_stack)
                    # Adding to stack -> hash map
                    if hash_code not in self._stack_hash_mapping:
                        self._stack_hash_mapping[hash_code] = valid_stack
                    # Adding to hash -> count map
                    if hash_code not in self._cluster_mapping:
                        self._cluster_mapping[hash_code] = 1
                    else:
                        self._cluster_mapping[hash_code] = self._cluster_mapping[hash_code] + 1
                except:
                    print("Something went wrong... TAT ...")

    def get_header(self):
        if not self._leak_log_header:
            return "EMPTY HEADER: Error or uninitialized. Check call sequence."
        try:
            header_dict = self._leak_log_header["header"]
            # pprint.pprint(header_dict)
            return header_dict
        except:
            print("Something went wrong getting the header dict...orz")

    def get_fd_list(self):
        if not self._leak_log_header:
            return "EMPTY HEADER: Error or uninitialized. Check call sequence."
        try:
            fd_list = self._leak_log_header["custom_long"]
            # pprint.pprint(fd_list)
            return fd_list
        except:
            print("Something went wrong getting the fd list...orz")

    def get_top_k_stack_hash(self, k):
        k = min(k, len(self._cluster_mapping))
        assert(k > 0)
        heap = []
        for _, (key, value) in enumerate(self._cluster_mapping.items()):
            if type(key) is int:
                heapq.heappush(heap, (value, key))
                if len(heap) > k:
                    heapq.heappop(heap)
        heap.sort(reverse=1)
        print(f"Printing the first {k} stack-hash with the most counts: ")
        for (count, hash_code) in heap:
            print("Count: "  + str(count) + "\tHash: " + str(hash_code))
        return heap

    def get_stack_by_hash(self, hash_code):
        if hash_code in self._stack_hash_mapping:
            return self._stack_hash_mapping[hash_code]
        else:
            return "STACK NOT PRESENT"

    def get_dictionary_map(self, only_stack=True):
        if only_stack:
            return {
                "Map : hash -> stack" : self._stack_hash_mapping
            }
        return {
            "Map : hash -> count" : self._cluster_mapping,
            "Map : hash -> stack" : self._stack_hash_mapping
        }

    def get_json_map(self, only_stack=True):
        return json.dumps(self.get_dictionary_map(only_stack))


if __name__ == '__main__':
    file_path = os.path.curdir + "/log/leak-r11s.log"
    clusterer = FdClusterer(file_path)
    clusterer.get_top_k_stack_hash(5)
    print("Printing Header Dict: ")
    pprint.pprint(clusterer.get_header())
    print("Printing FD List: ")
    pprint.pprint(clusterer.get_fd_list())
    pprint.pprint(clusterer.get_dictionary_map(False))


