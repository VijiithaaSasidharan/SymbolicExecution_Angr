import angr
import sys

from claripy import true


def is_successful(state):
    # Dump whatever has been printed out by the binary so far into a string.
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    # Return whether 'Good' and 'Fail' has been printed yet.
    return 'Good'.encode() in stdout_output  # :boolean


def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return 'Fail'.encode() in stdout_output  # :boolean


# path_to_binary = "pwd/pwd"  # :string/Users/bmk/Downloads/angr_ctf-master/650/ece650-a2
path_to_binary = "./pwd_args"  # :string
project = angr.Project(path_to_binary)
argv = [project.filename]
argv.append("-L")
main = project.loader.main_object.get_symbol("main")
initial_state = project.factory.blank_state(addr=main.rebased_addr)
entry_state = project.factory.entry_state(args=argv)


# Create a simulation manager initialized with the starting state. It provides
# a number of useful tools to search and execute the binary.
simulation = project.factory.simgr(entry_state, save_unsat=True)
# Explore the binary to attempt to find the address that prints "Good."

# Tell Angr to explore the binary and find any state that is_successful identfies
# as a successful state by returning True.
simulation.explore(find=is_successful, avoid=should_abort)

# Check that we have found a solution. The simulation.explore() method will
# set simulation.found to a list of the states that it could find that reach
# the instruction we asked it to search for. Remember, in Python, if a list
# is empty, it will be evaluated as false, otherwise true.

if simulation.found:
    # The explore method stops after it finds a single state that arrives at the
    # target address.
    s = simulation.found[0]
    print(s.posix.dumps(1))
    solution_state = simulation.found[0]
    # Print the string that Angr wrote to stdin to follow solution_state. This
    # is our solution.
    print("solution", solution_state.posix.dumps(sys.stdin.fileno()).decode())
else:
    # If Angr could not find a path that reaches print_good_address, throw an
    # error. Perhaps you mistyped the print_good_address?
    raise Exception('Could not find the solution')
