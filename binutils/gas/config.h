/* config.h.  Generated from config.in by configure.  */
/* config.in.  Generated from configure.ac by autoheader.  */

/* Check that config.h is #included before system headers
   (this works only for glibc, but that should be enough).  */
#if defined(__GLIBC__) && !defined(__FreeBSD_kernel__) && !defined(__CONFIG_H__)
#  error config.h must be #included before system headers
#endif
#define __CONFIG_H__ 1

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* Define if using AIX 5.2 value for C_WEAKEXT. */
/* #undef AIX_WEAK_SUPPORT */

/* assert broken? */
/* #undef BROKEN_ASSERT */

/* Define to one of `_getb67', `GETB67', `getb67' for Cray-2 and Cray-YMP
   systems. This function is required for `alloca.c' support on those systems.
   */
/* #undef CRAY_STACKSEG_END */

/* Compiling cross-assembler? */
/* #undef CROSS_COMPILE */

/* Define to 1 if using `alloca.c'. */
/* #undef C_ALLOCA */

/* Default architecture. */
#define DEFAULT_ARCH "x86_64"

/* Default CRIS architecture. */
/* #undef DEFAULT_CRIS_ARCH */

/* Default emulation. */
#define DEFAULT_EMULATION "i386elf"

/* Define if you want compressed debug sections by default. */
#define DEFAULT_FLAG_COMPRESS_DEBUG 1

/* Define to 1 if you want to generate ELF common symbols with the STT_COMMON
   type by default. */
#define DEFAULT_GENERATE_ELF_STT_COMMON 0

/* Define to 1 if you want to generate x86 relax relocations by default. */
#define DEFAULT_GENERATE_X86_RELAX_RELOCATIONS 1

/* Supported emulations. */
#define EMULATIONS &i386elf,

/* Define if you want run-time sanity checks. */
#define ENABLE_CHECKING 1

/* Define to 1 if translation of program messages to the user's native
   language is requested. */
#define ENABLE_NLS 1

/* Define to 1 if you have `alloca', as a function or macro. */
#define HAVE_ALLOCA 1

/* Define to 1 if you have <alloca.h> and it should be used (not on Ultrix).
   */
#define HAVE_ALLOCA_H 1

/* Define to 1 if you have the declaration of `asprintf', and to 0 if you
   don't. */
#define HAVE_DECL_ASPRINTF 1

/* Define to 1 if you have the declaration of `free', and to 0 if you don't.
   */
#define HAVE_DECL_FREE 1

/* Define to 1 if you have the declaration of `getenv', and to 0 if you don't.
   */
#define HAVE_DECL_GETENV 1

/* Is the prototype for getopt in <unistd.h> in the expected format? */
#define HAVE_DECL_GETOPT 1

/* Define to 1 if you have the declaration of `malloc', and to 0 if you don't.
   */
#define HAVE_DECL_MALLOC 1

/* Define to 1 if you have the declaration of `mempcpy', and to 0 if you
   don't. */
#define HAVE_DECL_MEMPCPY 1

/* Define to 1 if you have the declaration of `realloc', and to 0 if you
   don't. */
#define HAVE_DECL_REALLOC 1

/* Define to 1 if you have the declaration of `stpcpy', and to 0 if you don't.
   */
#define HAVE_DECL_STPCPY 1

/* Define to 1 if you have the declaration of `strstr', and to 0 if you don't.
   */
#define HAVE_DECL_STRSTR 1

/* Define to 1 if you have the declaration of `vsnprintf', and to 0 if you
   don't. */
#define HAVE_DECL_VSNPRINTF 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define if your <locale.h> file defines LC_MESSAGES. */
#define HAVE_LC_MESSAGES 1

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if you have the <locale.h> header file. */
#define HAVE_LOCALE_H 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `remove' function. */
/* #undef HAVE_REMOVE */

/* Define to 1 if you have the `sbrk' function. */
#define HAVE_SBRK 1

/* Define to 1 if you have the `setlocale' function. */
#define HAVE_SETLOCALE 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strsignal' function. */
#define HAVE_STRSIGNAL 1

/* Define if <sys/stat.h> has struct stat.st_mtim.tv_nsec */
#define HAVE_ST_MTIM_TV_NSEC 1

/* Define if <sys/stat.h> has struct stat.st_mtim.tv_sec */
#define HAVE_ST_MTIM_TV_SEC 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <time.h> header file. */
#define HAVE_TIME_H 1

/* Define if <time.h> has struct tm.tm_gmtoff. */
#define HAVE_TM_GMTOFF 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the `unlink' function. */
#define HAVE_UNLINK 1

/* Define to 1 if you have the <windows.h> header file. */
/* #undef HAVE_WINDOWS_H */

/* Using i386 COFF? */
/* #undef I386COFF */

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* Using m68k COFF? */
/* #undef M68KCOFF */

/* Using m88k COFF? */
/* #undef M88KCOFF */

/* Default CPU for MIPS targets. */
/* #undef MIPS_CPU_STRING_DEFAULT */

/* Generate 64-bit code by default on MIPS targets. */
/* #undef MIPS_DEFAULT_64BIT */

/* Choose a default ABI for MIPS targets. */
/* #undef MIPS_DEFAULT_ABI */

/* Define value for nds32_arch_name */
/* #undef NDS32_DEFAULT_ARCH_NAME */

/* Define default value for nds32_audio_ext */
/* #undef NDS32_DEFAULT_AUDIO_EXT */

/* Define default value for nds32_dx_regs */
/* #undef NDS32_DEFAULT_DX_REGS */

/* Define default value for nds32_perf_ext */
/* #undef NDS32_DEFAULT_PERF_EXT */

/* Define default value for nds32_perf_ext2 */
/* #undef NDS32_DEFAULT_PERF_EXT2 */

/* Define default value for nds32_string_ext */
/* #undef NDS32_DEFAULT_STRING_EXT */

/* Define if environ is not declared in system header files. */
/* #undef NEED_DECLARATION_ENVIRON */

/* Define if errno is not declared in system header files. */
/* #undef NEED_DECLARATION_ERRNO */

/* Define if ffs is not declared in system header files. */
/* #undef NEED_DECLARATION_FFS */

/* Define if free is not declared in system header files. */
/* #undef NEED_DECLARATION_FREE */

/* Define if malloc is not declared in system header files. */
/* #undef NEED_DECLARATION_MALLOC */

/* Define if sbrk is not declared in system header files. */
/* #undef NEED_DECLARATION_SBRK */

/* Define if strstr is not declared in system header files. */
/* #undef NEED_DECLARATION_STRSTR */

/* a.out support? */
/* #undef OBJ_MAYBE_AOUT */

/* b.out support? */
/* #undef OBJ_MAYBE_BOUT */

/* COFF support? */
/* #undef OBJ_MAYBE_COFF */

/* ECOFF support? */
/* #undef OBJ_MAYBE_ECOFF */

/* ELF support? */
/* #undef OBJ_MAYBE_ELF */

/* generic support? */
/* #undef OBJ_MAYBE_GENERIC */

/* SOM support? */
/* #undef OBJ_MAYBE_SOM */

/* Name of package */
#define PACKAGE "gas"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME "gas"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "gas 2.30"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "gas"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "2.30"

/* Define if defaulting to ELF on SCO 5. */
/* #undef SCO_ELF */

/* If using the C implementation of alloca, define if you know the
   direction of stack growth for your system; otherwise it will be
   automatically deduced at runtime.
	STACK_DIRECTION > 0 => grows toward higher addresses
	STACK_DIRECTION < 0 => grows toward lower addresses
	STACK_DIRECTION = 0 => direction of growth unknown */
/* #undef STACK_DIRECTION */

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Using strict COFF? */
/* #undef STRICTCOFF */

/* Define if you can safely include both <string.h> and <strings.h>. */
#define STRING_WITH_STRINGS 1

/* Target alias. */
#define TARGET_ALIAS "x86_64-pc-linux-gnu"

/* Define as 1 if big endian. */
/* #undef TARGET_BYTES_BIG_ENDIAN */

/* Canonical target. */
#define TARGET_CANONICAL "x86_64-pc-linux-gnu"

/* Target CPU. */
#define TARGET_CPU "x86_64"

/* Target OS. */
#define TARGET_OS "linux-gnu"

/* Define if default target is PowerPC Solaris. */
/* #undef TARGET_SOLARIS_COMMENT */

/* Define if target is Symbian OS. */
/* #undef TARGET_SYMBIAN */

/* Target vendor. */
#define TARGET_VENDOR "pc"

/* Target specific CPU. */
/* #undef TARGET_WITH_CPU */

/* Use b modifier when opening binary files? */
/* #undef USE_BINARY_FOPEN */

/* Use emulation support? */
/* #undef USE_EMULATIONS */

/* Allow use of E_MIPS_ABI_O32 on MIPS targets. */
/* #undef USE_E_MIPS_ABI_O32 */

/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
# define _ALL_SOURCE 1
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
/* Enable threading extensions on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
# define _POSIX_PTHREAD_SEMANTICS 1
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
# define _TANDEM_SOURCE 1
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
# define __EXTENSIONS__ 1
#endif


/* Using cgen code? */
/* #undef USING_CGEN */

/* Version number of package */
#define VERSION "2.30"

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
# endif
#endif

/* Define to 1 if `lex' declares `yytext' as a `char *' by default, not a
   `char[]'. */
#define YYTEXT_POINTER 1

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */

/* Define to 1 if on MINIX. */
/* #undef _MINIX */

/* Define to 2 if the system does not provide POSIX.1 features except with
   this defined. */
/* #undef _POSIX_1_SOURCE */

/* Define to 1 if you need to in order for `stat' and other things to work. */
/* #undef _POSIX_SOURCE */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif
