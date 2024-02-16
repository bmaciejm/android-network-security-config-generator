# This is a sample Python script.
import argparse
import sys


# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.

class ConfigGenerator:

    def __init__(self, namespace):
        pass

    def proceed(self):
        pass


# interactive mode and "all in" mode, the all in will be required for the UI tool, also it might
# be required from all the beginning as it potentially can be used for automation on CI

def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press ⌘F8 to toggle the breakpoint.


def interactive_mode():
    pass


def parse_args(args) -> argparse.Namespace:
    parser = argparse.ArgumentParser(args)
    parser.add_argument("-i", help="Run in interactive mode", action='store_true')
    return parser.parse_args()


if __name__ == '__main__':
    parse_args(sys.argv[1:])
