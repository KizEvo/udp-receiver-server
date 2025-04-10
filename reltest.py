import sys
import json
import numpy as np
import matplotlib.pyplot as plt


def find_missing_packages(arr):
    if not arr:  # Check if array is empty
        return []

    # Get the maximum number to know the full range
    max_num = max(arr)
    # Create a set for O(1) lookup
    num_set = set(arr)
    # List to store missing numbers
    missing = []

    # Check each number from 1 to max_num
    for i in range(1, max_num + 1):
        if i not in num_set:
            missing.append(i)

    return missing


def read_in():
    # Read data from stdin
    lines = sys.stdin.readlines()
    return json.loads(lines[0])


def main():
    # get our data as an array from read_in()
    inputs = read_in()

    # get package time elapsed array
    package_time_elapsed = inputs[0]

    # get package failure array
    package_failure = inputs[1]

    # get gateway missed package array
    package_gateway_missed = inputs[2]

    # create array for package time elapsed
    np_package_time_elapsed = np.array(package_time_elapsed)
    np_x_package = np.arange(1, np_package_time_elapsed.size + 1, 1)

    number_of_plot_row = 1
    number_of_plot_col = 1

    # create array for package failure
    np_package_failure = np.array(package_failure)
    if np_package_failure.size > 0:
        np_x_package_failure = np.arange(1, np_package_failure[-1] + 1, 1)
        np_y_package_failure = np.array(
            [0 if i in np_package_failure else 1 for i in np_x_package_failure])
        number_of_plot_row = number_of_plot_row + 1

    # create array for gateway missed package
    np_package_gateway_missed = np.array(package_gateway_missed)
    if np_package_gateway_missed.size > 0:
        np_x_package_gateway_missed = np.arange(
            1, np_package_gateway_missed[-1] + 1, 1)
        np_y_package_gateway_missed = np.array(
            [0 if i in np_package_gateway_missed else 1 for i in np_x_package_gateway_missed])
        number_of_plot_row = number_of_plot_row + 1

    # plot
    plt.figure()
    idx = 1
    if number_of_plot_row >= 1:
        plt.subplot(number_of_plot_row, number_of_plot_col, idx)
        plt.plot(np_x_package, np_package_time_elapsed)
        plt.xticks(np_x_package)  # Show all x-ticks
        plt.title("MCU time encryption interval")
        plt.xlabel("Package number")
        plt.ylabel("Time (us)")
        plt.subplots_adjust(left=0.2, hspace=0.5)

    if np_package_failure.size > 0:
        idx = idx + 1
        plt.subplot(number_of_plot_row, number_of_plot_col, idx)
        plt.ylim(-0.1, 1.1)
        plt.plot(np_x_package_failure, np_y_package_failure)
        plt.yticks([0, 1])  # Show only 0 and 1 on y-axis
        plt.xticks(np_x_package_failure)  # Show all x-ticks
        plt.title("Network server decrypt package")
        plt.xlabel("Package number")
        plt.ylabel("Success rate")

    if np_package_gateway_missed.size > 0:
        idx = idx + 1
        plt.subplot(number_of_plot_row, number_of_plot_col, idx)
        plt.ylim(-0.1, 1.1)
        plt.plot(np_x_package_gateway_missed, np_y_package_gateway_missed)
        plt.yticks([0, 1])  # Show only 0 and 1 on y-axis
        plt.xticks(np_x_package_gateway_missed)  # Show all x-ticks
        plt.title("Network server failed to get package")
        plt.xlabel("Package number")
        plt.ylabel("Success rate")

        # show the result
    plt.show()


# start process
if __name__ == '__main__':
    main()
