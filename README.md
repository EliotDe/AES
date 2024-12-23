# AES Cipher Implementation (C#)

This project is a very basic implementation of the AES (Advanced Encryption Standard) algorithm in C#. It was designed as a personal exercise to understand AES and other Feistel cipher-like encryption techniques. The project provides an in-depth exploration of symmetric encryption, focusing on AES’s internals, encryption rounds, and key expansion process. It has, by no means, been developed with upmost security in mind.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [How to Run](#how-to-run)
- [Implementation Details](#implementation-details)
- [Contributing](#contributing)
- [License](#license)

## Overview

AES is one of the most widely used symmetric encryption algorithms. It operates on fixed-size blocks of data (128 bits) and supports key sizes of 128, 192, and 256 bits. This project allows you to explore how AES works by implementing it in C#, with a focus on understanding the various steps involved, including:
- **Key expansion**: Generation of round keys from the initial cipher key.
- **SubBytes**: A non-linear substitution step.
- **ShiftRows**: A transposition step.
- **MixColumns**: A mixing transformation for diffusion.
- **AddRoundKey**: Combining the data with round keys.

This implementation aims to highlight the mathematical foundation of AES and its similarity to Feistel cipher structures, making it a great learning tool for anyone wanting to dive deep into encryption algorithms.

## Features

- AES encryption and decryption with key sizes of 128 bits.
- Manual key expansion process.
- Support for both encryption and decryption rounds.
- Clear separation between key stages and transformation steps.
- Implementation of the core AES transformations: SubBytes, ShiftRows, MixColumns, and AddRoundKey.
  
## How to Run

### Prerequisites
- .NET 6 or higher (or any version compatible with your project setup).
- Visual Studio or any C# IDE.

### Running the Project
1. Clone this repository:
    ```bash
    git clone https://github.com/EliotDe/AES.git
    ```
2. Open the project in Visual Studio or another IDE that supports C#.
3. Build and run the project to see the AES encryption and decryption in action.

## Contributing

- Contributions to this project are welcome! If you find any bugs, issues, or have suggestions for improvements, feel free to open an issue or submit a pull request. Please make sure to follow the coding style used in the project and include relevant tests for new features or fixes.

### Steps to contribute:
1. Fork this repository.
2. Clone your fork to your local machine.
3. Create a new branch for your feature or fix.
4. Commit your changes and push them to your fork.
5. Open a pull request with a description of what you've done.

## Liscence

This project is licensed under the MIT License - see the LICENSE file for details.

