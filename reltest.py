import sys
import json
import numpy as np
import matplotlib.pyplot as plt

# Read data from stdin


def read_in():
    lines = sys.stdin.readlines()
    return json.loads(lines[0])


def main():
    # get our data as an array from read_in()
    inputs = read_in()

    # get package time elapsed array
    package_time_elapsed = inputs[0]

    # get package failure array
    package_failure = inputs[1]

    # create array for package time elapsed
    np_package_time_elapsed = np.array(package_time_elapsed)
    np_x_package = np.arange(1, np_package_time_elapsed.size + 1, 1)

    # create array for package failure
    np_package_failure = np.array(package_failure)
    if np_package_failure.size > 0:
        np_x_package_failure = np.arange(1, np_package_failure[-1] + 1, 1)
        np_y_package_failure = np.array(
            [0 if i in np_package_failure else 1 for i in np_x_package_failure])
    else:
        np_x_package_failure = np_x_package
        np_y_package_failure = np.ones(np_package_time_elapsed.size, dtype=int)

    # plot
    plt.figure()
    plt.subplot(211)
    plt.plot(np_x_package, np_package_time_elapsed)
    plt.xticks(np_x_package)  # Show all x-ticks
    plt.title("MCU time encryption interval")
    plt.xlabel("Package number")
    plt.ylabel("Time (ns)")
    plt.subplots_adjust(left=0.2, hspace=0.5)

    plt.subplot(212)
    plt.ylim(-0.1, 1.1)
    plt.plot(np_x_package_failure, np_y_package_failure, 'o')
    plt.yticks([0, 1])  # Show only 0 and 1 on y-axis
    plt.xticks(np_x_package_failure)  # Show all x-ticks
    plt.title("Network server fails to decrypt package")
    plt.xlabel("Package number")
    plt.ylabel("Success rate")

    # show the result
    plt.show()


# start process
if __name__ == '__main__':
    main()
