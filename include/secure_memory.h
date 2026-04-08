#pragma once

// Prevents the process from generating core dumps on crash,
// stopping sensitive data from being written to disk.
void setCoreDumpLimits();

// Locks a memory region to prevent the OS from swapping it to disk.
// Call on any allocation containing sensitive data such as keys or passwords.
void lockMemoryPages();

// Securely zeroes a memory region before freeing to prevent secrets
// from lingering in freed memory. -- to be implemented
void secureZero();
