// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

// Prepared source only. Match the Rust kernel's exact 256-bit semantics.
contract Kernel {
    function run(uint256 seed, uint32 steps) external pure returns (bool success, uint256 value) {
        if (steps > 4096) return (false, seed);
        value = seed;
        unchecked {
            for (uint32 i = 0; i < steps; ++i) {
                value = value * 3 + 1;
            }
        }
        return (true, value);
    }
}
