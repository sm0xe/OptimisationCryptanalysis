#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.70])
AC_INIT([OptimizationCryptanalysis], [1.0], [karlaho@stud.ntnu.no])
AC_CONFIG_SRCDIR([CPP/src/cryptanalysis.cpp])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AM_INIT_AUTOMAKE
AC_PROG_CXX

# Checks for libraries.
AC_CHECK_LIB([boost_serialization], [cpp_int])
AC_CHECK_LIB([pagmo], [algorithm])
AC_CHECK_LIB([tbb], [main])

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL

# Checks for library functions.
AC_CHECK_FUNCS([pow])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
