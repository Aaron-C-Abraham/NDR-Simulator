# NDR Simulator

A simulation platform designed to test, validate, and demonstrate the functionality of the Network Detection and Response (NDR) Agent.

## Overview

The NDR Simulator provides an environment for evaluating NDR agent behavior and observing its response to simulated network activities. It is intended for development, testing, and demonstration purposes.

---

## Prerequisites

Ensure the following software is installed before proceeding:

| Dependency | Required Version |
|------------|------------------|
| Go (Golang) | 1.26.3 or later |
| Node.js | 22.22 or later |
| npm | 10.9 or later |

You can verify your installations using:

```bash
go version
node --version
npm --version
```

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Aaron-C-Abraham/NDR-Simulator.git
cd NDR-Simulator
```

### 2. Install Frontend Dependencies

From the project root directory, install the required npm packages:

```bash
npm install
```

### 3. Build the Go Components

Navigate to the Go source directory:

```bash
cd netsim-ndr/src
```

Build all Go source files:

```bash
go build -o ndr_sim .
```

### 4. Run the Simulator Backend

Move the generated executable outside the `src` directory if required, then execute it:

```bash
./ndr_sim
```

---

## Starting the Application

Open a new terminal in the project root directory and start the application:

```bash
npm run start
```

Once both the backend executable and frontend application are running, the NDR Simulator will be fully operational.

---

## Notes

- Ensure that the backend executable is running before starting the frontend application.
- Verify that all required dependencies are installed and available in your system's PATH.
