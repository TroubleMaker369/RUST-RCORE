#						关于RSIV-RUSTOS的一些自我总结

## 第零章

关于本次os：

出自实验指导书[rCore-Tutorial-Book 第三版 — rCore-Tutorial-Book-v3 0.1 文档 (rcore-os.github.io)](https://rcore-os.github.io/rCore-Tutorial-Book-v3/)

源代码出自[rcore-os/rCore-Tutorial-v3: v3.5 https://rcore-os.github.io/rCore-Tutorial-Book-v3/index.html](https://github.com/rcore-os/rCore-Tutorial-v3)

​	写这篇总结的关于操作系统的层次如何理清楚，我觉得还是按实验指导书上的顺序来，这样循序渐进，也能学到更多，**关于本次os的代码，是用RUST写的，采用精简指令集**。为什么用rust？因为本人该学期一直在学习rust+操作系统(哈哈，具体可以去实验指导书上学习)。经学长推荐，在暑假准备手敲一遍该os源码，在一遍一遍的实现中，我也发现了rust语言的安全性的一些体现，也由衷的感叹道rCore内核源码的逻辑的精妙之处，我觉得对于目前的我来说，这个操作系统的代码的书写逻辑，布局，已经是非常非常非常棒的了，所以我才决定一点一点的敲出来，也是为了加强rust的熟练程度，和操作系统的认知深度。小弟是只小弱鸡，只能先学习，再创新。

​	另外在文章的最后我会加上自己的虚拟磁盘（百度网盘），里面有我对每一章代码的注释，结合实验指导书，以后自己复习应该会更加的方便快捷，本文仅仅是作为我个人复习使用，路过的大佬勿喷。本实验指导书上的信息量足够大，希望我以后可以再回过头来继续研究学习。

## 第一章



![](https://pic.imgdb.cn/item/60fdfe085132923bf8174be6.png)



### 应用执行环境

![](https://pic.imgdb.cn/item/60fe00c05132923bf81cb3b8.jpg)

应用程序通过函数调用可以调用编程语言提供的标准库或者其他三方库对外提供的功能强大的函数接口，内核位于内核态，他上面的一切位于用户态，他可以对用户态的应用的执行进行监护和管理，某些功能总要直接或间接的通过内核/操作系统提供的 **系统调用** (System Call) 来实现

### 平台目标三元组

x86_64-unknown-linux-gnu 从这个看来可以解释为  CPU架构是X86_64，CPU厂商unknown , 操作系统的LINUX，运行时库是gnu libc（封装了Linux系统调用，并提供POSIX接口为主的函数库）

​																					**这里解释了为什么该os采用RISC-V而不是X86系列架构**：

x86 架构为了在升级换代的同时保持对基于旧版架构应用程序/内核的兼容性，存在大量的历史包袱，也就是一些对于目前的应用场景没有任何意义，但又必须花大量时间正确设置才能正常使用 CPU 的奇怪设定。为了建立并维护架构的应用生态，这确实是必不可少的，但站在教学的角度几乎完全是在浪费时间。而新生的 RISC-V 架构十分简洁，架构文档需要阅读的核心部分不足百页，且这些功能已经足以用来构造一个具有相当抽象能力的内核了。

这里给上网址[RISC-V手册 (ict.ac.cn)](http://crva.ict.ac.cn/documents/RISC-V-Reader-Chinese-v2p1.pdf)

我们的选择是`riscv64gc-unknown-none-elf`   elf表示没有运行时库，

### **RISC-V 指令集拓展**

- RV32/64I：每款处理器都必须实现的基本整数指令集。在 RV32I 中，每个通用寄存器的位宽为 32 位；在 RV64I 中则为 64 位。它可以用来模拟绝大多数标准指令集拓展中的指令，除了比较特殊的 A 拓展，因为它需要特别的硬件支持。
- M 拓展：提供整数乘除法相关指令。
- A 拓展：提供原子指令和一些相关的内存同步机制，这个后面会展开。
- F/D 拓展：提供单/双精度浮点数运算支持。
- C 拓展：提供压缩指令拓展。

裸机平台：目标平台不存在任何操作系统支持，于是 Rust 并没有为这个目标平台支持完整的标准库 std。

### rust语言简单的特点

**rust 语言是一种面向系统（包括操作系统）开发的语言，所以在 Rust 语言生态中，有很多三方库也不依赖标准库 std 而仅仅依赖核心库 core**。对它们的使用可以很大程度上减轻我们的编程负担。它们是我们能够在裸机平台挣扎求生的最主要倚仗，也是大部分运行在没有操作系统支持的 Rust 嵌入式软件的必备。第一章构建的操作系统比较简单只要大概了解布局和原理就可。

#### 移除 println! 宏

我们首先在 `os` 目录下新建 `.cargo` 目录，并在这个目录下创建 `config` 文件，并在里面输入如下内容：

```rust
# os/.cargo/config
[build]
target = "riscv64gc-unknown-none-elf"
```

这会对于 Cargo 工具在 os 目录下的行为进行调整：现在默认会使用 riscv64gc 作为目标平台而不是原先的默认 x86_64-unknown-linux-gnu。事实上，这是一种编译器运行所在的平台与编译器生成可执行文件的目标平台不同（分别是后者和前者）的情况。这是一种 **交叉编译** (Cross Compile)。



main的开头加#![no_std]告诉 Rust 编译器不使用 Rust 标准库 std 转而使用核心库 core

#### 提供语义项panic_handler

```rust
use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
```

注意，**panic 处理函数的函数签名**需要一个 `PanicInfo` 的不可变借用作为输入参数，它在核心库中得以保留

### 构建用户态执行环境

 #### 用户态最小化执行环境

通过下面代码可以让rust编译器找到执行环境的入口

```rust
#[no_mangle]
extern "C" fn _start() {
    loop{};
}
```

如果现在编译的话，会触发段错误，因为我们目前的执行环境还缺了一个退出机制。

```rust
#![feature(llvm_asm)]

const SYSCALL_EXIT: usize = 93;

fn syscall(id: usize, args: [usize; 3]) -> isize {
    let mut ret: isize;
    unsafe {
        llvm_asm!("ecall"
            : "={x10}" (ret)
            : "{x10}" (args[0]), "{x11}" (args[1]), "{x12}" (args[2]), "{x17}" (id)
            : "memory"
            : "volatile"
        );
    }
    ret
}

pub fn sys_exit(xstate: i32) -> isize {
    syscall(SYSCALL_EXIT, [xstate as usize, 0, 0])
}

#[no_mangle]
extern "C" fn _start() {
    sys_exit(9);
}
```

这里只需知道 `_start` 函数调用了一个 `sys_exit` 函数，来向操作系统发出一个退出服务的系统调用请求，并传递给OS的退出码为 `9` 。

#### 有显示支持的用户态执行环境

Rust 的 core 库内建了以一系列帮助实现显示字符的基本 Trait 和数据结构，函数等，我们可以对其中的关键部分进行扩展，就可以实现定制的 `println!` 功能

**sys_write系统调用的封装：**

```rust
const SYSCALL_WRITE: usize = 64;

pub fn sys_write(fd: usize, buffer: &[u8]) -> isize {
  syscall(SYSCALL_WRITE, [fd, buffer.as_ptr() as usize, buffer.len()])
}
```

下面展示基于write  trait实现的数据结构

```rust
struct Stdout;

impl Write for Stdout {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        sys_write(1, s.as_bytes());
        Ok(())
    }
}

pub fn print(args: fmt::Arguments) {
    Stdout.write_fmt(args).unwrap();
}
```

然后实现rust语言的格式化宏

```rust
#[macro_export]
macro_rules! print {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::print(format_args!($fmt $(, $($arg)+)?));
    }
}

#[macro_export]
macro_rules! println {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        print(format_args!(concat!($fmt, "\n") $(, $($arg)+)?));
    }
}
```

关于rust宏的实现之前学习过，但是仅仅只是了解，下去继续了解。现在我们就可以使用println!来打印了.

```rust
#[no_mangle]
extern "C" fn _start() {
    println!("Hello, world!");
    sys_exit(9);
}
```

### 构建逻辑运行时执行环境

本节正式实现自己裸机上的最小执行环境，关注的问题有一下几点：

- 物理内存的 DRAM 位置（放应用程序的地方）和应用程序的内存布局（如何在 DRAM 中放置应用程序的各个部分）
- SBI 的字符输出接口（执行环境提供的输出字符服务，可以被应用程序使用）
- 应用程序的初始化（起始的指令位置，对 `栈 stack` 和 `bss` 的初始化）、

#### 硬件组成和裸机启动的过程

- 启动OS：硬件启动后，**会有一段代码（一般统称为bootloader）对硬件进行初始化，让包括内核在内的系统软件得以运行**；
- OS准备好应用程序执行的环境：**要运行该应用程序的时候，内核分配相应资源，将程序代码和数据载入内存，并赋予 CPU 使用权，由此应用程序可以运行**；
- 应用程序开始执行：程序员编写的代码是应用程序的一部分，它需要**标准库/核心库**进行一些初始化工作后才能运行

为此我们必须明确三点：

1. 应用程序的裸机硬件系统是啥样子的
2. 系统在做这些初始化工作之前处于什么状态
3. 在做完初始化工作也就是即将执行 main 函数之前又处于什么状态

关于硬件的组成，这里是实验指导书上的内容：

- 我们采用的是QEMU软件 `qemu-system-riscv64` 来模拟一台RISC-V 64计算机，具体的硬件规格是：

  外设：16550A UART，virtio-net/block/console/gpu等和设备树硬件特权级：priv v1.10， user v2.2中断控制器：可参数化的CLINT（核心本地中断器）、可参数化的PLIC（平台级中断控制器）可参数化的RAM内存可配置的多核 RV64GC M/S/U mode CPU

这里列出的硬件功能很多还用不上，不过在后面的章节中会逐步用到上面的硬件功能，以支持更加强大的操作系统能力。

在QEMU模拟的硬件中，物理内存和外设都是通过对内存读写的方式来进行访问，下面列出了QEMU模拟的物理内存空间。

```
// qemu/hw/riscv/virt.c
static const struct MemmapEntry {
    hwaddr base;
    hwaddr size;
} virt_memmap[] = {
    [VIRT_DEBUG] =       {        0x0,         0x100 },
    [VIRT_MROM] =        {     0x1000,        0xf000 },
    [VIRT_TEST] =        {   0x100000,        0x1000 },
    [VIRT_RTC] =         {   0x101000,        0x1000 },
    [VIRT_CLINT] =       {  0x2000000,       0x10000 },
    [VIRT_PCIE_PIO] =    {  0x3000000,       0x10000 },
    [VIRT_PLIC] =        {  0xc000000, VIRT_PLIC_SIZE(VIRT_CPUS_MAX * 2) },
    [VIRT_UART0] =       { 0x10000000,         0x100 },
    [VIRT_VIRTIO] =      { 0x10001000,        0x1000 },
    [VIRT_FLASH] =       { 0x20000000,     0x4000000 },
    [VIRT_PCIE_ECAM] =   { 0x30000000,    0x10000000 },
    [VIRT_PCIE_MMIO] =   { 0x40000000,    0x40000000 },
    [VIRT_DRAM] =        { 0x80000000,           0x0 },
};
```

- 到现在为止，其中比较重要的两个是：

  VIRT_DRAM：DRAM的内存起始地址是 `0x80000000` ，缺省大小为128MB。在本书中一般限制为8MB。VIRT_UART0：串口相关的寄存器起始地址是 `0x10000000` ，范围是 `0x100` ，我们通过访问这段特殊的区域来实现字符输入输出的管理与控制。

DRAM的内存起始地址是 `0x80000000`，这里的0x80000000是存放我们bootloaderd开始。

#### 裸机启动过程

**QEMU 模拟 CPU 加电的执行过程**

CPU加电后的执行细节与具体硬件相关，我们这里以QEMU模拟器为具体例子简单介绍一下。

这需要从 CPU 加电后如何初始化，如何执行第一条指令开始讲起。对于我们采用的QEMU模拟器而言，它模拟了一台标准的RISC-V64计算机。我们启动QEMU时，可设置一些参数，在RISC-V64计算机启动执行前，先在其模拟的内存中放置好BootLoader程序和操作系统的二进制代码。**这可以通过查看 `os/Makefile` 文件中包含 `qemu-system-riscv64` 的相关内容来了解**。

- `-bios $(BOOTLOADER)` **这个参数意味着硬件内存中的固定位置 `0x80000000` 处放置了一个BootLoader程序–RustSBI**（戳 [附录 C：深入机器模式：RustSBI](https://rcore-os.github.io/rCore-Tutorial-Book-v3/appendix-c/index.html) 可以进一步了解RustSBI。）。
- `-device loader,file=$(KERNEL_BIN),addr=$(KERNEL_ENTRY_PA)` **这个参数表示硬件内存中的特定位置 `$(KERNEL_ENTRY_PA)` 放置了操作系统的二进制代码 `$(KERNEL_BIN)` 。 `$(KERNEL_ENTRY_PA)` 的值是 `0x80200000` 。**

当我们执行包含上次参数的qemu-system-riscv64软件，就意味给这台虚拟的RISC-V64计算机加电了。此时，CPU的其它通用寄存器清零， 而PC寄存器会指向 `0x1000` 的位置。 这个 `0x1000` 位置上是CPU加电后执行的第一条指令（固化在硬件中的一小段引导代码），它会很快跳转到 `0x80000000` 处， 即RustSBI的第一条指令。RustSBI完成基本的硬件初始化后， 会跳转操作系统的二进制代码 `$(KERNEL_BIN)` 所在内存位置 `0x80200000` ，执行操作系统的第一条指令。 这时我们的编写的操作系统才开始正式工作。



**为啥在 `0x80000000` 放置 `Bootloader` ？因为这是QEMU的硬件模拟代码中设定好的 `Bootloader` 的起始地址。**

**为啥在 `0x80200000` 放置 `os` ？因为这是 `Bootloader--RustSBI` 的代码中设定好的 `os` 的起始地址。**



操作系统和SBI之间的关系

SBI是RISC-V的一种底层规范，他向操作系统提供服务，比如一些：关机，显示字符串等。这些通过操作系统也能实现，但比较繁琐，既然后rustSBI服务，我们操作系统直接调用就好了

#### 实现关机功能

SBI提供的关机功能 `SBI_SHUTDOWN` 

```rust
fn sbi_call(which: usize, arg0: usize, arg1: usize, arg2: usize) -> usize {
    let mut ret;
    unsafe {
        llvm_asm!("ecall"
            : "={x10}" (ret)
            : "{x10}" (arg0), "{x11}" (arg1), "{x12}" (arg2), "{x17}" (which)

            
            
            
const SBI_SHUTDOWN: usize = 8;
pub fn shutdown() -> ! {
    sbi_call(SBI_SHUTDOWN, 0, 0, 0);
    panic!("It should shutdown!");
}

#[no_mangle]
extern "C" fn _start() {
    shutdown();
}
```

关于特权级的划分

- User Mode : 用户特权级（一些应用所在的等级）
- Supervisor Mode:操作系统位于 很强大的内核特权级
- Machine Mode：RustSBI位于完全掌控机器的机器特权级

#### 设置正确的程序内存布局

 我们修改 Cargo 的配置文件来使用我们自己的链接脚本 `os/src/linker.ld` 而非使用默认的内存布局

```rust
[build]
target = "riscv64gc-unknown-none-elf" 

[target.riscv64gc-unknown-none-elf]
rustflags = [
    "-Clink-arg=-Tsrc/linker.ld", "-Cforce-frame-pointers=yes"
]
```

下面是具体的链接脚本

```rust
OUTPUT_ARCH(riscv)
ENTRY(_start)
BASE_ADDRESS = 0x80200000;

SECTIONS
{
    . = BASE_ADDRESS;
    skernel = .;

    stext = .;
    .text : {
        *(.text.entry)
        *(.text .text.*)
    }

    . = ALIGN(4K);
    etext = .;
    srodata = .;
    .rodata : {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    }

    . = ALIGN(4K);
    erodata = .;
    sdata = .;
    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
    }

    . = ALIGN(4K);
    edata = .;
    .bss : {
        *(.bss.stack)
        sbss = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
    }

    . = ALIGN(4K);
    ebss = .;
    ekernel = .;

    /DISCARD/ : {
        *(.eh_frame)
    }
}
```

这里我们设置了目标平台riscv，和整个程序的入口点_star，以及我们操作系统存放的起始地址0x80200000

关于内容的解释

```assembly
.rodata : {
    *(.rodata)
}
```

冒号前面表示最终生成的可执行文件的一个段的名字，花括号内按照放置顺序描述将所有输入目标文件的哪些段放在这个段中**，每一行格式为 `<ObjectFile>(SectionName)`，表示目标文件 `ObjectFile` 的名为 `SectionName` 的段需要被放进去**。我们也可以 使用通配符来书写 `<ObjectFile>` 和 `<SectionName>` 分别表示可能的输入目标文件和段名。因此，最终的合并结果是，**在最终可执行文件 中各个常见的段 `.text, .rodata .data, .bss` 从低地址到高地址按顺序放置，每个段里面都包括了所有输入目标文件的同名段， 且每个段都有两个全局符号给出了它的开始和结束地址**（比如 `.text` 段的开始和结束地址分别是 `stext` 和 `etext` ）。

1. 如何做到执行环境的初始化代码被放在内存上以 `0x80200000` 开头的区域上？

   > 在链接脚本第 7 行，我们将当前地址设置为 `BASE_ADDRESS` 也即 `0x80200000` ，然后从这里开始往高地址放置各个段。第一个被放置的 是 `.text` ，而里面第一个被放置的又是来自 `entry.asm` 中的段 `.text.entry`，这个段恰恰是含有两条指令的执行环境初始化代码， 它在所有段中最早被放置在我们期望的 `0x80200000` 处。



这个时候我们的内存布局大致就已经完成了，如果这个时候我们去执行，会发现系统挂掉，应为我们没没用设置好栈



#### 正确配置站空间布局

我们要写一小段汇编代码 `entry.asm` 来帮助建立好栈空间

```assembly
    .section .text.entry
    .globl _start
_start:
    la sp, boot_stack_top
    call rust_main

    .section .bss.stack
    .globl boot_stack
boot_stack:
    .space 4096 * 16
    .globl boot_stack_top
boot_stack_top:
```

可以到，第一部分我们放在.text.entry中，这里是代码的段，目的是初始化栈。第二部分是.bss.stack 可以看到我们设置了栈空间大小64KB和栈顶位置。第二条指令则是通过伪指令 `call` 函数调用 `rust_main` ，这里的 `rust_main` 是一个我们稍后自己编写的应用 入口。因此初始化任务非常简单：正如上面所说的一样，只需要设置栈指针 sp，随后跳转到应用入口即可。这两条指令单独作为一个名为 `.text.entry` 的段，且全局符号 `_start` 给出了段内第一条指令的地址。

```rust
#![no_std]      //不实用标准库
#![no_main]   //表示不使用默认的入口函数。避免panic_handler的发生
#![feature(global_asm)]//引入global_asm!
#![feature(llvm_asm)]
#![feature(panic_info_message)]  //通过 PanicInfo::message 获取报错信息。

#[macro_use]
mod console;
mod lang_items;
mod sbi;

global_asm!(include_str!("entry.asm"));   
//include_str!将entry.asm中的汇编指令转换为字符串
//global宏 将转换得到的字符串嵌入到代码中
fn clear_bss(){
    extern "C"{
        fn sbss();
        fn ebss();
    }
    (sbss as usize..ebss as usize).for_each(|a| {
        unsafe {
            (a as *mut u8).write_volatile(0)  //对裸指针解引用是不安全的
        }
    }
    );
}
/

#[no_mangle]//通过宏将 rust_main 标记为 #[no_mangle] 以避免编译器对它的 名字进行混淆
pub fn rust_main() -> ! {
    extern "C" {
        fn stext();
        fn etext();
        fn srodata();
        fn erodata();
        fn sdata();
        fn edata();
        fn sbss();
        fn ebss();
        fn boot_stack();
        fn boot_stack_top();
    }
    clear_bss();
    println!("Hello, world!");
    println!(".text [{:#x}, {:#x}]", stext as usize, etext as usize);
    println!(".rodata [{:#x}, {:#x}]", srodata as usize, erodata as usize);
    println!(".data [{:#x}, {:#x}]", sdata as usize, edata as usize);
    println!(
        "boot_stack [{:#x}, {:#x}]",
        boot_stack as usize, boot_stack_top as usize
    );
    println!(".bss [{:#x}, {:#x}]", sbss as usize, ebss as usize);
    panic!("Shutdown machine!");  //Panicked at src/main.rs:52 Shutdown machine!
}

```

这里我直接给出了main.rs中的最终的代码

#### 清空.bss段

与内存相关的部分太容易出错了。所以，我们再仔细检查代码后，发现在嵌入式系统中常见的 **清零 .bss段** 的工作并没有完成。

由于一般应用程序的 `.bss` 段**在程序正式开始运行之前会被执环境（系统库或操作系统内核）固定初始化为零**，**因此在 ELF 文件中，为了节省磁盘空间，只会记录 `.bss` 段的位置**，且应用程序的假定在它执行前，其 `.bss段` 的数据内容都已是 `全0` 。 如果这块区域不是全零，且执行环境也没提前清零，那么会与应用的假定矛盾，导致程序出错。对于在裸机上执行的应用程序，其执行环境（就是QEMU模拟硬件+“三叶虫”操作系统内核）将可执行文件加载到内存的时候，并负责将 `.bss` 所分配到的内存区域全部清零。

我们需要提供清零的 `clear_bss()` 函数。此函数属于执行环境，并在执行环境调用 应用程序的 `rust_main` 主函数前，把 `.bss` 段的全局数据清零

在程序内自己进行清零的时候，我们就不用去解析 ELF（此时也没有 ELF 可供解析）了，而是通过链接脚本 `linker.ld` 中给出的全局符号 `sbss` 和 `ebss` 来确定 `.bss` 段的位置。

#### 添加裸机打印相关函数

```rust
const SBI_CONSOLE_PUTCHAR: usize = 1;

pub fn console_putchar(c: usize) {
    syscall(SBI_CONSOLE_PUTCHAR, [c, 0, 0]);
}

impl Write for Stdout {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        //sys_write(STDOUT, s.as_bytes());
        for c in s.chars() {
            console_putchar(c as usize);
        }
        Ok(())
    }
}
```

这里就是将上一节调用的core中的write  换成了我们的SBI的SBI_CONSOLE_PUTCHAR，

```rust
// os/src/main.rs
#![feature(panic_info_message)]

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    if let Some(location) = info.location() {
        println!("Panicked at {}:{} {}", location.file(), location.line(), info.message().unwrap());
    } else {
        println!("Panicked: {}", info.message().unwrap());
    }
    shutdown()
}
```

关于panic函数，自然是在触发异常的时候通过#![feature(panic_info_message)]进行捕捉，然后处理。

### 理解应用程序和执行环境

关于理解应用程序和执行环境，我自认为总结的不到位，还是附上地址看原版，才更加有味道（实际上是懒！！）

[理解应用程序和执行环境 — rCore-Tutorial-Book-v3 0.1 文档 (rcore-os.github.io)](https://rcore-os.github.io/rCore-Tutorial-Book-v3/chapter1/4understand-prog.html)

![](https://pic.imgdb.cn/item/60fe1a695132923bf85a0796.png)



## 第二章：批处理系统

**本章的功能要求**

- 通过批处理支持多个程序的自动加载和运行
- 操作系统利用硬件特权级机制，实现对操作系统自身的保护

**批处理系统** (Batch System) 应运而生。它的核心思想是：将多个程序打包到一起输入计算机。而当一个程序运行结束后，计算机会 *自动* 加载下一个程序到内存并开始执行。这便是最早的真正意义上的操作系统。

### 特权级机制

为了保护我们批处理系统能不受影响的全程稳定的工作，单凭软件是很难做到的，需要CPU提供一种特权级隔离机制

通过：

- `ecall` ：具有用户态到内核态的执行环境切换能力的函数调用指令（RISC-V中就有这条指令）
- `eret` ：具有内核态到用户态的执行环境切换能力的函数返回指令（RISC-V中有类似的 `sret` 指令）

这两条指令我们可以特换特权级

#### RISCV特权级架构提供了下面4个

RISC-V 架构中一共定义了 4 种特权级：

| 级别 | 编码 | 名称                                |
| ---- | ---- | ----------------------------------- |
| 0    | 00   | 用户/应用模式 (U, User/Application) |
| 1    | 01   | 监督模式 (S, Supervisor)            |
| 2    | 10   | H, Hypervisor                       |
| 3    | 11   | 机器模式 (M, Machine)               |

关于H特权级在这个操作系统中未涉及，只有0 1 3

![](https://pic.imgdb.cn/item/60fe1d0e5132923bf8612457.png)

这张图片给出了能够支持运行 Unix 这类复杂系统的软件栈。其中 内核代码运行在 S 模式上；应用程序运行在 U 模式上。运行在 M 模式上的软件被称为 **监督模式执行环境** (SEE, Supervisor Execution Environment) ，这是站在运行在 S 模式上的软件的视角来看，它的下面也需要一层执行环境支撑，因此被命名为 SEE，它需要在相比 S 模式更高的特权级下运行， 一般情况下在 M 模式上运行。

![](https://pic.imgdb.cn/item/60fe1da45132923bf862b7c9.jpg)

上图展示了一系列特权级的切换

#### risc-v的特权指令

与特权级无关的一般的指令和**通用寄存器** `x0~x31` 在任何特权级都可以任意执行。

每个特权级都对应一些特殊指令和 **控制状态寄存器** (CSR, Control and Status Register) ，来控制该特权级的某些行为并描述其状态。当然特权指令不只是具有有读写 CSR 的指令，还有其他功能的特权指令。



在RISC-V中，会有两类低优先级U模式下运行高优先级S模式的指令：

- 指令本身属于高特权级的指令，如 `sret` 指令（表示从S模式返回到U模式）。
- 指令访问了 [S模式特权级下才能访问的寄存器](https://rcore-os.github.io/rCore-Tutorial-Book-v3/chapter2/4trap-handling.html#term-s-mod-csr) 或内存，如表示S模式系统状态的 **控制状态寄存器** `sstatus` 等。

| 指令               | 含义                                                         |
| ------------------ | ------------------------------------------------------------ |
| sret               | 从S模式返回U模式。在U模式下执行会产生非法指令异常            |
| wfi                | 处理器在空闲时进入低功耗状态等待中断。在U模式下执行会尝试非法指令异常 |
| sfence.vma         | 刷新TLB缓存。在U模式下执行会尝试非法指令异常                 |
| 访问S模式CSR的指令 | 通过访问 [sepc/stvec/scause/sscartch/stval/sstatus/satp等CSR](https://rcore-os.github.io/rCore-Tutorial-Book-v3/chapter2/4trap-handling.html#term-s-mod-csr) 来改变系统状态。在U模式下执行会尝试非法指令异常 |

### 实现应用程序

本节主要讲解如何设计实现被批处理系统逐个加载并运行的应用程序

涉及的设计实现要点是：

- 应用程序的内存布局
- 应用程序发出的系统调用



#![feature(linkage)] 为了链接操作，需要在lib.rs开头加入

#### 内存布局

- 将程序的起始物理地址调整为 `0x80400000` ，三个应用程序都会被加载到这个物理地址上运行；
- 将 `_start` 所在的 `.text.entry` 放在整个程序的开头，也就是说批处理系统只要在加载之后跳转到 `0x80400000` 就已经进入了 用户库的入口点，并会在初始化之后跳转到应用程序主逻辑；
- 提供了最终生成可执行文件的 `.bss` 段的起始和终止地址，方便 `clear_bss` 函数使用。



#### 系统调用

在子模块 `syscall` 中我们作为应用程序来通过 `ecall` 调用批处理系统提供的接口，由于应用程序运行在 U 模式， `ecall` 指令会触发 名为 `Environment call from U-mode` 的异常，并 Trap 进入 S 模式执行批处理系统针对这个异常特别提供的服务代码。由于这个接口处于 S 模式的批处理系统和 U 模式的应用程序之间，从上一节我们可以知道，这个接口可以被称为 ABI 或者系统调用。现在我们不关心底层的批处理系统如何 提供应用程序所需的功能，只是站在应用程序的角度去使用即可

```rust
/// 功能：将内存中缓冲区中的数据写入文件。
/// 参数：`fd` 表示待写入文件的文件描述符；
///      `buf` 表示内存中缓冲区的起始地址；
///      `len` 表示内存中缓冲区的长度。
/// 返回值：返回成功写入的长度。
/// syscall ID：64
fn sys_write(fd: usize, buf: *const u8, len: usize) -> isize;

/// 功能：退出应用程序并将返回值告知批处理系统。
/// 参数：`xstate` 表示应用程序的返回值。
/// 返回值：该系统调用不应该返回。
/// syscall ID：93
fn sys_exit(xstate: usize) -> !;
```

约定寄存器 `a0~a6` 保存系统调用的参数， `a0~a1` 保存系统调用的返回值。有些许不同的是 寄存器 `a7` 用来传递 syscall ID，这是因为所有的 syscall 都是通过 `ecall` 指令触发的，除了各输入参数之外我们还额外需要一个寄存器 来保存要请求哪个系统调用。由于这超出了 Rust 语言的表达能力，我们需要在代码中使用内嵌汇编来完成参数/返回值绑定和 `ecall` 指令的插入

```rust
const SYSCALL_WRITE: usize = 64;
const SYSCALL_EXIT: usize = 93;
fn syscall(id: usize, args: [usize; 3]) -> isize {
    let mut ret: isize;  //ret必须是可变绑定，将他和x10寄存器进行绑定，便可以拿到返回值
    unsafe {
        llvm_asm!("ecall"
            : "={x10}" (ret)  
            : "{x10}" (args[0]), "{x11}" (args[1]), "{x12}" (args[2]), "{x17}" (id)
            : "memory"
            : "volatile"
        );
    }
    ret
}
pub fn sys_write(fd:usize,buffer: &[u8])->isize{
    syscall(SYSCALL_WRITE,[fd,buffer.as_ptr() as usize ,buffer.len()])
}
pub fn sys_exit(exit_code: i32) -> isize {
    syscall(SYSCALL_EXIT, [exit_code as usize, 0, 0])
}
```

关于rust中llvm_asm的完整格式的解析

Rust 中的 `llvm_asm!` 宏的完整格式如下：

```
llvm_asm!(assembly template
   : output operands
   : input operands
   : clobbers
   : options
);
```

**"={x10}" (ret)**： 指定输出操作数。这里由于我们的系统调用返回值只有一个 `isize` ，根据调用规范它会被保存在 `a0` 寄存器中。在双引号内，我们 可以对于使用的操作数进行限制，由于是输出部分，限制的开头必须是一个 `=` 。我们可以在限制内使用一对花括号再加上一个寄存器的名字告诉 编译器汇编的输出结果会保存在这个寄存器中。我们将声明出来用来保存系统调用返回值的变量 `ret` 包在一对普通括号里面放在操作数限制的 后面，这样可以把变量和寄存器建立联系。于是，在系统调用返回之后我们就能在变量 `ret` 中看到返回值了。注意，变量 `ret` 必须为可变 绑定，否则无法通过编译，这也说明在 unsafe 块内编译器还是会进行力所能及的安全检查。

"{**x10}" (args[0]), "{x11}" (args[1]), "{x12}" (args[2]), "{x17}" (id)**  ：指定输入操作数。由于是输入部分，限制的开头不用加上 `=` 。同时在限制中设置使用寄存器 `a0~a2` 来保存系统调用的参数，以及 寄存器 `a7` 保存 syscall ID ，而它们分别 `syscall` 的参数变量 `args` 和 `id` 绑定。

**"memory"：**第 9 行用于告知编译器插入的汇编代码会造成的一些影响以防止编译器在不知情的情况下误优化。常用的使用方法是告知编译器某个寄存器在执行嵌入 的汇编代码中的过程中会发生变化。我们这里则是告诉编译器：程序在执行嵌入汇编代码中指令的时候会修改内存。这能给编译器提供更多信息以生成正确的代码。

**: "volatile"：**用于告知编译器将我们在程序中给出的嵌入汇编代码保持原样放到最终构建的可执行文件中。如果不这样做的话，编译器可能会把它和其他代码 一视同仁并放在一起进行一些我们期望之外的优化。为了保证语义的正确性，一些比较关键的汇编代码需要加上该选项。

#### 编译生成应用程序二进制码

这里简要介绍一下应用程序的自动构建。只需要在 `user` 目录下 `make build` 即可：

1. 对于 `src/bin` 下的每个应用程序，在 `target/riscv64gc-unknown-none-elf/release` 目录下生成一个同名的 ELF 可执行文件；
2. 使用 objcopy 二进制工具将上一步中生成的 ELF 文件删除所有 ELF header 和符号得到 `.bin` 后缀的纯二进制镜像文件。它们将被链接 进内核并由内核在合适的时机加载到内存。

### 实现批处理操作系统

这主要包括两个方面：

- 静态编码：通过一定的编程技巧，把应用程序代码和批处理操作系统代码“绑定”在一起。
- 动态加载：基于静态编码留下的“绑定”信息，操作系统可以找到应用程序文件二进制代码的起始地址和长度，并能加载到内存中运行。

#### 将应用程序链接到内核

看一看link_app.S

```assembly
    .align 3
    .section .data
    .global _num_app
_num_app:
    .quad 3
    .quad app_0_start
    .quad app_1_start
    .quad app_2_start
    .quad app_2_end

    .section .data
    .global app_0_start
    .global app_0_end
app_0_start:
    .incbin "../user/target/riscv64gc-unknown-none-elf/release/00hello_world.bin"
app_0_end:

    .section .data
    .global app_1_start
    .global app_1_end
app_1_start:
    .incbin "../user/target/riscv64gc-unknown-none-elf/release/01store_fault.bin"
app_1_end:

    .section .data
    .global app_2_start
    .global app_2_end
app_2_start:
    .incbin "../user/target/riscv64gc-unknown-none-elf/release/02power.bin"
app_2_end:

```

开始的三个数据段分别插入了三个应用程序的二进制镜像，并且各自有一对全局符号 `app_*_start, app_*_end` 指示它们的 开始和结束位置。而第 3 行开始的另一个数据段相当于一个 64 位整数数组。数组中的第一个元素表示应用程序的数量，后面则按照顺序放置每个应用 程序的起始地址，最后一个元素放置最后一个应用程序的结束位置。这样每个应用程序的位置都能从该数组中相邻两个元素中得知。这个数组所在的位置 同样也由全局符号 `_num_app` 所指示。

```rust
//batch.rs
use core::cell::RefCell;
use lazy_static::*;
use crate::trap::TrapContext;

const USER_STACK_SIZE: usize = 4096 * 2;
const KERNEL_STACK_SIZE: usize = 4096 * 2;
const MAX_APP_NUM: usize = 16;
const APP_BASE_ADDRESS: usize = 0x80400000;
const APP_SIZE_LIMIT: usize = 0x20000;

//内核栈和用户栈都是以全局变量的形式实例化在批处理系统的.bss段中的
#[repr(align(4096))]
struct KernelStack {
    data: [u8; KERNEL_STACK_SIZE],
}

#[repr(align(4096))]
struct UserStack {
    data: [u8; USER_STACK_SIZE],
}

static KERNEL_STACK: KernelStack = KernelStack {
     data: [0; KERNEL_STACK_SIZE] 
};
static USER_STACK: UserStack = UserStack {
     data: [0; USER_STACK_SIZE]
};

impl KernelStack {
    fn get_sp(&self) -> usize {
        self.data.as_ptr() as usize + KERNEL_STACK_SIZE
    }
    pub fn push_context(&self, cx: TrapContext) -> &'static mut TrapContext {
        let cx_ptr = (self.get_sp() - core::mem::size_of::<TrapContext>()) as *mut TrapContext;
        unsafe { 
            *cx_ptr = cx; 
        }
        unsafe{
             cx_ptr.as_mut().unwrap() 
        }
    }
}

impl UserStack {
    fn get_sp(&self) -> usize {
        self.data.as_ptr() as usize + USER_STACK_SIZE
    }
}

struct AppManager{
    inner:RefCell<AppManagerInner>,
}
struct AppManagerInner{
    num_app:usize,
    current_app:usize,
    app_start:[usize;MAX_APP_NUM+1],
}
unsafe impl Sync for AppManager {}

impl AppManagerInner {
    pub fn print_app_info(&self) {    //逐个的打印app的信息
        println!("[kernel] num_app = {}", self.num_app);
        for i in 0..self.num_app {
            println!("[kernel] app_{} [{:#x}, {:#x})", i, self.app_start[i], self.app_start[i + 1]);
        }
    }
    unsafe fn load_app(&self,app_id:usize){
        if app_id>=self.num_app{         //如果当前的app大于所有的app数量 ， 则退出
            panic!("All app complate!");
        }
        println!("[kernel] Loading app_{}", app_id);
        llvm_asm!("fence.i"::::"volatile");
        (APP_BASE_ADDRESS..APP_BASE_ADDRESS+APP_SIZE_LIMIT).for_each(|addr|{
            (addr as *mut u8).write_volatile(0);
        });   //申请一段APP_SIZE_LIMIT大小的内存， 始址在APP_BASE_ADDRESS 0x8040000000
  
        let app_src=core::slice::from_raw_parts(
            self.app_start[app_id] as *const u8, self.app_start[app_id+1] -self.app_start[app_id]);
        let app_dst = core::slice::from_raw_parts_mut(APP_BASE_ADDRESS as *mut u8, app_src.len());
        app_dst.copy_from_slice(app_src);
    }

    pub fn get_current_app(&self) -> usize {   //获取当前运行的app是第几个
        self.current_app 
    }

    pub fn move_to_next_app(&mut self) {      //跳到下一个app去执行
        self.current_app += 1;
    }
}
lazy_static!{     //保证内部可变性，使用recell
    static ref APP_MANAGER:AppManager=AppManager{
        inner:RefCell::new({
            extern "C" {
                fn _num_app();            //初始化num_app的代码
            }
            let num_app_ptr = _num_app as usize as *const usize;   //拿到该数据段的起始地址空间
            let num_app=unsafe{
                num_app_ptr.read_volatile()         //读取一个字节的内存，则他的第一个字节存储的是app的数量
            };
            let mut app_start:[usize;MAX_APP_NUM+1]=[0;MAX_APP_NUM+1];
            let app_start_raw:&[usize]= unsafe{
                core::slice::from_raw_parts(num_app_ptr.add(1),num_app+1)      //读取每个app的起始地址
            };
            app_start[..=num_app].copy_from_slice(app_start_raw);    //拷贝
            AppManagerInner{
                num_app,
                current_app:0,
                app_start,
            }
        }),
    };
}

pub fn init() {
    print_app_info();
}

pub fn print_app_info() {   
    APP_MANAGER.inner.borrow().print_app_info();
}

pub fn run_next_app(){
    let current_app=APP_MANAGER.inner.borrow().get_current_app();
    unsafe{
        APP_MANAGER.inner.borrow().load_app(current_app);
    }
    extern "C"{
        fn __restore(cx_addr:usize);
    }
    unsafe{
        __restore(KERNEL_STACK.push_context(
            TrapContext::app_init_context(APP_BASE_ADDRESS, USER_STACK.get_sp())
        ) as *const _ as usize
    );
    }
    panic!("Unreachable in batch::run_current_app!");
}
```

我们利用 `RefCell` 来提供 **内部可变性** (Interior Mutability)， 所谓的内部可变性就是指在我们只能拿到 `AppManager` 的不可变借用，意味着同样也只能 拿到 `AppManagerInner` 的不可变借用的情况下依然可以修改 `AppManagerInner` 里面的字段。 使用 `RefCell::borrow/RefCell::borrow_mut` 分别可以拿到 `RefCell` 里面内容的不可变借用/可变借用， `RefCell` 会在运行时维护当前它管理的对象的已有借用状态，并在访问对象时进行借用检查。于是 `RefCell::borrow_mut` 就是我们实现内部可变性的关键。

我们使用了外部库 `lazy_static` 提供的 `lazy_static!` 宏。要引入这个外部库，我们需要加入依赖：

```
# os/Cargo.toml

[dependencies]
lazy_static = { version = "1.4.0", features = ["spin_no_std"] }
```

`lazy_static!` 宏提供了**全局变量的运行时初始化功能**。一般情况下，全局变量必须在编译期设置一个初始值，但是有些全局变量依赖于运行期间 才能得到的数据作为初始值。这导致这些全局变量需要在运行时发生变化，也即重新设置初始值之后才能使用。如果我们手动实现的话有诸多不便之处， 比如需要把这种全局变量声明为 `static mut` 并衍生出很多 unsafe code。这种情况下我们可以使用 `lazy_static!` 宏来帮助我们解决 这个问题。这里我们借助 `lazy_static!` 声明了一个 `AppManager` 结构的名为 `APP_MANAGER` 的全局实例，且只有在它第一次被使用到 的时候才会进行实际的初始化工作。

因此，借助 Rust 核心库提供的 `RefCell` 和外部库 `lazy_static!`，我们就能在避免 `static mut` 声明的情况下以更加优雅的Rust风格使用全局变量。

`batch` 子模块对外暴露出如下接口：

- `init` ：调用 `print_app_info` 的时候第一次用到了全局变量 `APP_MANAGER` ，它也是在这个时候完成初始化；
- `run_next_app` ：批处理操作系统的核心操作，即加载并运行下一个应用程序。当批处理操作系统完成初始化或者一个应用程序运行结束或出错之后会调用 该函数。我们下节再介绍其具体实现。

### 实现特权级的切换

这一节往后我准备按照自己对代码的理解来讲，具体代码涉及到的细节，请看实验指导书，或者另一个笔记

![](https://pic.imgdb.cn/item/60fe2b915132923bf88bee47.jpg)



## 第三章多道程序和分时多任务



我们重新实现了一个链接脚本来，通过它来实现的app的数据布局

```rust
 1 # user/build.py
 2
 3 import os
 4
 5 base_address = 0x80400000
 6 step = 0x20000
 7 linker = 'src/linker.ld'
 8
 9 app_id = 0
10 apps = os.listdir('src/bin')
11 apps.sort()
12 for app in apps:
13     app = app[:app.find('.')]
14     lines = []
15     lines_before = []
16     with open(linker, 'r') as f:
17         for line in f.readlines():
18             lines_before.append(line)
19             line = line.replace(hex(base_address), hex(base_address+step*app_id))
20             lines.append(line)
21     with open(linker, 'w+') as f:
22         f.writelines(lines)
23     os.system('cargo build --bin %s --release' % app)
24     print('[build.py] application %s start with address %s' %(app, hex(base_address+step*app_id)))
25     with open(linker, 'w+') as f:
26         f.writelines(lines_before)
27     app_id = app_id + 1
```

- 第 16~22 行，找到 `src/linker.ld` 中的 `BASE_ADDRESS = 0x80400000;` 这一行，并将后面的地址 替换为和当前应用对应的一个地址；
- 第 23 行，使用 `cargo build` 构建当前的应用，注意我们可以使用 `--bin` 参数来只构建某一个应用；
- 第 25~26 行，将 `src/linker.ld` 还原。

#### 多道程序加载

应用的加载方式也和上一章的有所不同。上一章中讲解的加载方法是让所有应用都共享同一个固定的加载物理地址。也是因为这个原因，内存中同时最多只能驻留一个应用，当它运行完毕或者出错退出的时候由操作系统的 `batch` 子模块加载一个新的应用来替换掉它。本章中，所有的应用在内核初始化的时候就一并被加载到内存中。为了避免覆盖，它们自然需要被加载到不同的物理地址。这是通过调用 `loader` 子模块的 `load_apps` 函数实现的：

```rust
 1 // os/src/loader.rs
 2
 3 pub fn load_apps() {
 4     extern "C" { fn _num_app(); }
 5     let num_app_ptr = _num_app as usize as *const usize;
 6     let num_app = get_num_app();
 7     let app_start = unsafe {
 8         core::slice::from_raw_parts(num_app_ptr.add(1), num_app + 1)
 9     };
10     // clear i-cache first
11     unsafe { llvm_asm!("fence.i" :::: "volatile"); }
12     // load apps
13     for i in 0..num_app {
14         let base_i = get_base_i(i);
15         // clear region
16         (base_i..base_i + APP_SIZE_LIMIT).for_each(|addr| unsafe {
17             (addr as *mut u8).write_volatile(0)
18         });
19         // load app from data section to memory
20         let src = unsafe {
21             core::slice::from_raw_parts(
22                 app_start[i] as *const u8,
23                 app_start[i + 1] - app_start[i]
24             )
25         };
26         let dst = unsafe {
27             core::slice::from_raw_parts_mut(base_i as *mut u8, src.len())
28         };
29         dst.copy_from_slice(src);
30     }
31 }
```

可以看出，第 i 个应用被加载到以物理地址 `base_i` 开头的一段物理内存上，而 `base_i` 的计算方式如下：

```rust
1 // os/src/loader.rs
2
3 fn get_base_i(app_id: usize) -> usize {
4     APP_BASE_ADDRESS + app_id * APP_SIZE_LIMIT
5 }
```



#### 执行应用程序

当多道程序的初始化放置工作完成，或者是某个应用程序运行结束或出错的时候，我们要调用 run_next_app 函数切换到下一个应用程序。此时 CPU 运行在 S 特权级的操作系统中，而操作系统希望能够切换到 U 特权级去运行应用程序。这一过程与上章的 [执行应用程序](https://rcore-os.github.io/rCore-Tutorial-Book-v3/chapter2/4trap-handling.html#ch2-app-execution) 一节的描述类似。相对不同的是，操作系统知道每个应用程序预先加载在内存中的位置，这就需要设置应用程序返回的不同 Trap 上下文（Trap上下文中保存了 放置程序起始地址的``epc`` 寄存器内容）：

### 任务切换

为了提高效率，我们需要引入新的操作系统概念 **任务** 、 **任务切换** 、**任务上下文**

![](https://pic.imgdb.cn/item/60fe338d5132923bf8ac73f6.png)

![](https://pic.imgdb.cn/item/60fe33bc5132923bf8aced35.png)

下面我们给出 `__switch` 的实现：

```
 1# os/src/task/switch.S
 2
 3.altmacro
 4.macro SAVE_SN n
 5    sd s\n, (\n+1)*8(sp)
 6.endm
 7.macro LOAD_SN n
 8    ld s\n, (\n+1)*8(sp)
 9.endm
10    .section .text
11    .globl __switch
12__switch:
13    # __switch(
14    #     current_task_cx_ptr2: &*const TaskContext,
15    #     next_task_cx_ptr2: &*const TaskContext
16    # )
17    # push TaskContext to current sp and save its address to where a0 points to
18    addi sp, sp, -13*8
19    sd sp, 0(a0)
20    # fill TaskContext with ra & s0-s11
21    sd ra, 0(sp)
22    .set n, 0
23    .rept 12
24        SAVE_SN %n
25        .set n, n + 1
26    .endr
27    # ready for loading TaskContext a1 points to
28    ld sp, 0(a1)
29    # load registers in the TaskContext
30    ld ra, 0(sp)
31    .set n, 0
32    .rept 12
33        LOAD_SN %n
34        .set n, n + 1
35    .endr
36    # pop TaskContext
37    addi sp, sp, 13*8
38    ret
```

我们手写汇编代码来实现 `__switch` 。可以看到它的函数原型中的两个参数分别是当前 Trap 执行流和即将被切换到的 Trap 执行流的 `task_cx_ptr2` ，从 [RISC-V 调用规范](https://rcore-os.github.io/rCore-Tutorial-Book-v3/chapter1/4understand-prog.html#term-calling-convention) 可以知道它们分别通过寄存器 `a0/a1` 传入。

阶段 [2] 体现在第 18~26 行。第 18 行在 A 的内核栈上预留任务上下文的空间，然后将当前的栈顶位置保存下来。接下来就是逐个对寄存器进行保存，从中我们也能够看出 `TaskContext` 里面究竟包含哪些寄存器：

```
1// os/src/task/context.rs
2
3#[repr(C)]
4pub struct TaskContext {
5    ra: usize,
6    s: [usize; 12],
7}
```

这里面只保存了 `ra` 和被调用者保存的 `s0~s11` 。`ra` 的保存很重要，它记录了 `__switch` 返回之后应该到哪里继续执行，从而在切换回来并 `ret` 之后能到正确的位置。而保存调用者保存的寄存器是因为，调用者保存的寄存器可以由编译器帮我们自动保存。我们会将这段汇编代码中的全局符号 `__switch` 解释为一个 Rust 函数：

```
 1// os/src/task/switch.rs
 2
 3global_asm!(include_str!("switch.S"));
 4
 5extern "C" {
 6    pub fn __switch(
 7        current_task_cx_ptr2: *const usize,
 8        next_task_cx_ptr2: *const usize
 9    );
10}
```

我们会调用该函数来完成切换功能而不是直接跳转到符号 `__switch` 的地址。因此在调用前后 Rust 编译器会自动帮助我们插入保存/恢复调用者保存寄存器的汇编代码。

仔细观察的话可以发现 `TaskContext` 很像一个普通函数栈帧中的内容。正如之前所说， `__switch` 的实现除了换栈之外几乎就是一个普通函数，也能在这里得到体现。尽管如此，二者的内涵却有着很大的不同。

剩下的汇编代码就比较简单了。读者可以自行对照注释看看图示中的后面几个阶段各是如何实现的。另外，后面会出现传给 `__switch` 的两个参数相同，也就是某个 Trap 执行流自己切换到自己的情形，请读者对照图示思考目前的实现能否对它进行正确处理。

### 多道程序与协作式调度

- 任务运行状态：任务从开始到结束执行过程中所处的不同运行状态：未初始化、准备执行、正在执行、已退出
- 任务控制块：管理程序的执行过程的任务上下文，控制程序的执行与暂停
- 任务相关系统调用：应用程序和操作系统直接的接口，用于程序主动暂停 `sys_yield` 和主动退出 `sys_exit`

#### yield 系统调用

![](https://pic.imgdb.cn/item/60fe34be5132923bf8af6052.png)

不同颜色对应不同的应用

sys_yield的缺点

当应用调用它主动交出 CPU 使用权之后，它下一次再被允许使用 CPU 的时间点与内核的调度策略与当前的总体应用执行情况有关，很有可能远远迟于该应用等待的事件（如外设处理完请求）达成的时间点。这就会造成该应用的响应延迟不稳定，有可能极高。比如，设想一下，敲击键盘之后隔了数分钟之后才能在屏幕上看到字符，这已经超出了人类所能忍受的范畴。

![](https://pic.imgdb.cn/item/60fe373b5132923bf8b66cfe.png)





![](https://pic.imgdb.cn/item/60fe37bf5132923bf8b99fb6.png)

### 分时多任务系统与抢占式调度

**时钟中断与计时器**

由于需要一种计时机制，RISC-V 架构要求处理器要有一个内置时钟，其频率一般低于 CPU 主频。此外，还有一个计数器统计处理器自上电以来经过了多少个内置时钟的时钟周期。在 RV64 架构上，该计数器保存在一个 64 位的 CSR `mtime` 中，我们无需担心它的溢出问题，在内核运行全程可以认为它是一直递增的。

另外一个 64 位的 CSR `mtimecmp` 的作用是：一旦计数器 `mtime` 的值超过了 `mtimecmp`，就会触发一次时钟中断。这使得我们可以方便的通过设置 `mtimecmp` 的值来决定下一次时钟中断何时触发。

可惜的是，它们都是 M 特权级的 CSR ，而我们的内核处在 S 特权级，是不被硬件允许直接访问它们的。好在运行在 M 特权级的 SEE 已经预留了相应的接口，我们可以调用它们来间接实现计时器的控制：

```
// os/src/timer.rs

use riscv::register::time;

pub fn get_time() -> usize {
    time::read()
}
```

`timer` 子模块的 `get_time` 函数可以取得当前 `mtime` 计数器的值；

```
 1// os/src/sbi.rs
 2
 3const SBI_SET_TIMER: usize = 0;
 4
 5pub fn set_timer(timer: usize) {
 6    sbi_call(SBI_SET_TIMER, timer, 0, 0);
 7}
 8
 9// os/src/timer.rs
10
11use crate::config::CLOCK_FREQ;
12const TICKS_PER_SEC: usize = 100;
13
14pub fn set_next_trigger() {
15    set_timer(get_time() + CLOCK_FREQ / TICKS_PER_SEC);
16}
```

- 代码片段第 5 行， `sbi` 子模块有一个 `set_timer` 调用，是一个由 SEE 提供的标准 SBI 接口函数，它可以用来设置 `mtimecmp` 的值。

- 代码片段第 14 行， `timer` 子模块的 `set_next_trigger` 函数对 `set_timer` 进行了封装，它首先读取当前 `mtime` 的值，然后计算出 10ms 之内计数器的增量，再将 `mtimecmp` 设置为二者的和。这样，10ms 之后一个 S 特权级时钟中断就会被触发。

  至于增量的计算方式， `CLOCK_FREQ` 是一个预先获取到的各平台不同的时钟频率，单位为赫兹，也就是一秒钟之内计数器的增量。它可以在 `config` 子模块中找到。10ms 的话只需除以常数 `TICKS_PER_SEC` 也就是 100 即可。

后面可能还有一些计时的操作，比如统计一个应用的运行时长的需求，我们再设计一个函数：

```
// os/src/timer.rs

const MSEC_PER_SEC: usize = 1000;

pub fn get_time_ms() -> usize {
    time::read() / (CLOCK_FREQ / MSEC_PER_SEC)
}
```

`timer` 子模块的 `get_time_ms` 可以以毫秒为单位返回当前计数器的值，这让我们终于能对时间有一个具体概念了。实现原理就不再赘述。

我们也新增一个系统调用方便应用获取当前的时间，以毫秒为单位：

第三章新增系统调用（二）

```
/// 功能：获取当前的时间，以毫秒为单位。
/// 返回值：返回当前的时间，以毫秒为单位。
/// syscall ID：169
fn sys_get_time() -> isize;
```

它在内核中的实现只需调用 `get_time_ms` 函数即可。

#### 抢占式调度

有了时钟中断和计时器，抢占式调度就很容易实现了：

```
// os/src/trap/mod.rs

match scause.cause() {
    Trap::Interrupt(Interrupt::SupervisorTimer) => {
        set_next_trigger();
        suspend_current_and_run_next();
    }
}
```

我们只需在 `trap_handler` 函数下新增一个分支，当发现触发了一个 S 特权级时钟中断的时候，首先重新设置一个 10ms 的计时器，然后调用上一小节提到的 `suspend_current_and_run_next` 函数暂停当前应用并切换到下一个。

为了避免 S 特权级时钟中断被屏蔽，我们需要在执行第一个应用之前进行一些初始化设置：

```rust
 1// os/src/main.rs
 2
 3#[no_mangle]
 4pub fn rust_main() -> ! {
 5    clear_bss();
 6    println!("[kernel] Hello, world!");
 7    trap::init();
 8    loader::load_apps();
 9    trap::enable_timer_interrupt();
10    timer::set_next_trigger();
11    task::run_first_task();
12    panic!("Unreachable in rust_main!");
13}
14
15// os/src/trap/mod.rs
16
17use riscv::register::sie;
18
19pub fn enable_timer_interrupt() {
20    unsafe { sie::set_stimer(); }
21}
```

- 第 9 行设置了 `sie.stie` 使得 S 特权级时钟中断不会被屏蔽；
- 第 10 行则是设置第一个 10ms 的计时器。

这样，当一个应用运行了 10ms 之后，一个 S 特权级时钟中断就会被触发。由于应用运行在 U 特权级，且 `sie` 寄存器被正确设置，该中断不会被屏蔽，而是 Trap 到 S 特权级内的我们的 `trap_handler` 里面进行处理，并顺利切换到下一个应用。这便是我们所期望的抢占式调度机制。从应用运行的结果也可以看出，三个 `power` 系列应用并没有进行 yield ，而是由内核负责公平分配它们执行的时间片。

目前在等待某些事件的时候仍然需要 yield ，其中一个原因是为了节约 CPU 计算资源，另一个原因是当事件依赖于其他的应用的时候，由于只有一个 CPU ，当前应用的等待可能永远不会结束。这种情况下需要先将它切换出去，使得其他的应用到达它所期待的状态并满足事件的生成条件，再切换回来。

这里我们先通过 yield 来优化 **轮询** (Busy Loop) 过程带来的 CPU 资源浪费。在 `03sleep` 这个应用中：

```rust
// user/src/bin/03sleep.rs

#[no_mangle]
fn main() -> i32 {
    let current_timer = get_time();
    let wait_for = current_timer + 3000;
    while get_time() < wait_for {
        yield_();
    }
    println!("Test sleep OK!");
    0
}
```

它的功能是等待 3000ms 然后退出。可以看出，我们会在循环里面 `yield_` 来主动交出 CPU 而不是无意义的忙等。尽管我们不这样做，已有的抢占式调度还是会在它循环 10ms 之后切换到其他应用，但是这样能让内核给其他应用分配更多的 CPU 资源并让它们更早运行结束。

![](https://pic.imgdb.cn/item/60fe39555132923bf8bdc1b4.png)

## 第四章：地址空间

#### rust中动态内存分配

实现目标

- 初始时能提供一块大内存空间作为初始的“堆”。在没有分页机制情况下，这块空间是物理内存空间，否则就是虚拟内存空间。
- 提供在堆上分配一块内存的函数接口。这样函数调用方就能够得到一块地址连续的空闲内存块进行读写。
- 提供释放内存的函数接口。能够回收内存，以备后续的内存分配请求。
- 提供空闲空间管理的连续内存分配算法。能够有效地管理空闲快，这样就能够动态地维护一系列空闲和已分配的内存块。
- （可选）提供建立在堆上的数据结构和操作。有了上述基本的内存分配与释放函数接口，就可以实现类似动态数组，动态字典等空间灵活可变的堆数据结构，提高编程的灵活性。

#### 静态与动态内存分配

#### 静态分配

在编译的时候编译器已经知道它们类型的字节大小， 于是给它们分配一块等大的内存将它们存储其中，这块内存在变量所属函数的栈帧/数据段中的位置也已经被固定了下来

#### 动态分配

动态分配就是指应用不仅在自己的地址空间放置那些 自编译期开始就大小固定、用于静态内存分配的逻辑段（如全局数据段、栈段），还另外放置一个大小可以随着应用的运行动态增减 的逻辑段，它的名字叫做堆。同时，应用还要能够将这个段真正管理起来，即支持在运行的时候从里面分配一块空间来存放变量，而 在变量的生命周期结束之后，这块空间需要被回收以待后面的使用

#### Rust中的堆数据结构

1. 裸指针： `*const T/*mut T` 基本等价于 C/C++ 里面的普通指针 `T*` ，它自身的内容仅仅是一个地址。它最为灵活， 但是也最不安全。编译器只能对它进行最基本的可变性检查
2. 引用：自身的内容也仅仅是一个地址，但是 Rust 编译器会在编译的时候进行比较严格的 **借用检查** (Borrow Check) ，要求引用的生命周期必须在被借用的变量的生命周期之内，同时可变借用和不可变借用不能共存，一个 变量可以同时存在多个不可变借用，而可变借用同时最多只能存在一个。这能在编译期就解决掉很多内存不安全问题
3. 智能指针：不仅包含它指向的区域的地址，还含有一些额外的信息，因此这个类型的字节大小大于平台的位宽，属于一种胖指针。 从用途上看，它不仅可以作为一个媒介来访问它指向的数据，还能在这个过程中起到一些管理和控制的功能

rust中的智能指针

- `Box<T>` 在创建时会在堆上分配一个类型为 `T` 的变量，它自身也只保存在堆上的那个变量的位置。而和裸指针或引用 不同的是，当 `Box<T>` 被回收的时候，它指向的——也就是在堆上被动态分配的那个变量也会被回收
- `Rc<T>` 是一个单线程上使用的引用计数类型， `Arc<T>` 与其功能相同，只是它可以在多线程上使用。它提供了 多所有权，也即地址空间中同时可以存在指向同一个堆上变量的 `Rc<T>` 
- `Mutex<T>` 是一个互斥锁，在多线程中使用，它可以保护里层被动态分配到堆上的变量同一时间只有一个线程能对它 进行操作，从而避免数据竞争，这是并发安全的问题

我们通过 `RefCell<T>` 来获得内部可变性。可以将 `Mutex<T>` 看成 `RefCell<T>` 的多线程版本， 因为 `RefCell<T>` 是只能在单线程上使用的。而且 `RefCell<T>` 并不会在堆上分配内存，它仅用到静态内存 分配。



在该内核中动态内存分配器是用已有的伙伴分配器实现。首先添加 crate 依赖



```rust
# os/Cargo.toml

buddy_system_allocator = "0.6"
```

##### 这里的伙伴系统在后续的学习中可自己实现

```rust
use buddy_system_allocator::LockedHeap;
use crate::config::KERNEL_HEAP_SIZE;

#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap = LockedHeap::empty();

#[alloc_error_handler]
pub fn handle_alloc_error(layout: core::alloc::Layout) -> ! {
    panic!("Heap allocation error, layout = {:?}", layout);
}

static mut HEAP_SPACE: [u8; KERNEL_HEAP_SIZE] = [0; KERNEL_HEAP_SIZE];

pub fn init_heap() {
    unsafe {
        HEAP_ALLOCATOR
            .lock()
            .init(HEAP_SPACE.as_ptr() as usize, KERNEL_HEAP_SIZE);
    }
}

#[allow(unused)]
pub fn heap_test() {
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    extern "C" {
        fn sbss();
        fn ebss();
    }
    let bss_range = sbss as usize..ebss as usize;
    let a = Box::new(5);
    assert_eq!(*a, 5);
    assert!(bss_range.contains(&(a.as_ref() as *const _ as usize)));
    drop(a);
    let mut v: Vec<usize> = Vec::new();
    for i in 0..500 {
        v.push(i);
    }
    for i in 0..500 {
        assert_eq!(v[i], i);
    }
    assert!(bss_range.contains(&(v.as_ptr() as usize)));
    drop(v);
    println!("heap_test passed!");
}

```

### 地址空间



![](https://pic.imgdb.cn/item/60fe5f6b5132923bf84279dc.jpg)

分段内存管理

![](https://pic.imgdb.cn/item/60fe5fd85132923bf8442aae.jpg)

这个图是最古老的一种分段也叫插槽，为了降低内部碎片，出现了分段内存管理



![](https://pic.imgdb.cn/item/60fe60965132923bf846c9d0.jpg)

但明显分段会造成额外的外部碎片，之后就出现了分页

#### 分页内存管理

![](https://pic.imgdb.cn/item/60fe61225132923bf848c2f9.jpg)

#### SV39多级页表的具体实现

首先看看Satp寄存器的规格，他是存储某地址空间的页表的物理地址，可用于开启和切换地址空间

![](https://pic.imgdb.cn/item/60fe61af5132923bf84ad8e8.png)

下面分别是物理地址和虚拟地址的格式

![](https://pic.imgdb.cn/item/60fe623d5132923bf84d197e.png)

我们采用分页管理，单个页面的大小设置为 4KiB ，每个虚拟页面和物理页帧都对齐到这个页面大小，也就是说 虚拟/物理地址区间 [0,4KiB) 为第 0 个虚拟页面/物理页帧，而 [4KiB,8KiB) 为第 1 个，以此类推。 4KiB 需要用 12 位字节地址 来表示，因此虚拟地址和物理地址都被分成两部分：它们的低 12 位，即 [11:0] 被称为 **页内偏移** (Page Offset) ，它描述一个地址指向的字节在它所在页面中的相对位置。而虚拟地址的高 27 位，即 [38:12] 为 它的虚拟页号 VPN，同理物理地址的高 44 位，即 [55:12] 为它的物理页号 PPN，页号可以用来定位一个虚拟/物理地址 属于哪一个虚拟页面/物理页帧

关于分页的具体看流程图

![](https://pic.imgdb.cn/item/60fe6e025132923bf87bd6d7.png)

### 加载和执行应用程序

### 扩展任务控制块

为了让应用在运行时有一个安全隔离且符合编译器给应用设定的地址空间布局的虚拟地址空间，操作系统需要对任务进行更多的管理，所以任务控制块相比第三章也包含了更多内容：

```rust
// os/src/task/task.rs

pub struct TaskControlBlock {
    pub task_cx_ptr: usize,
    pub task_status: TaskStatus,
    pub memory_set: MemorySet,
    pub trap_cx_ppn: PhysPageNum,
    pub base_size: usize,
}
```

然后就是一些TCB的操作

```rust
 1// os/src/mm/page_table.rs
 2
 3pub fn translated_byte_buffer(
 4    token: usize,
 5    ptr: *const u8,
 6    len: usize
 7) -> Vec<&'static [u8]> {
 8    let page_table = PageTable::from_token(token);
 9    let mut start = ptr as usize;
10    let end = start + len;
11    let mut v = Vec::new();
12    while start < end {
13        let start_va = VirtAddr::from(start);
14        let mut vpn = start_va.floor();
15        let ppn = page_table
16            .translate(vpn)
17            .unwrap()
18            .ppn();
19        vpn.step();
20        let mut end_va: VirtAddr = vpn.into();
21        end_va = end_va.min(VirtAddr::from(end));
22        v.push(&ppn.get_bytes_array()[start_va.page_offset()..end_va.page_offset()]);
23        start = end_va.into();
24    }
25    v
}
```

## 第五章：进程及进程管理



```
build.rs(修改：基于应用名的应用构建器)
loader.rs(修改：基于应用名的应用加载器)
main.rs(修改)
mm(修改：为了支持本章的系统调用对此模块做若干增强)
fs.rs(修改：新增 sys_read)
mod.rs(修改：新的系统调用的分发处理)
process.rs（修改：新增 sys_getpid/fork/exec/waitpid）
manager.rs(新增：任务管理器，为上一章任务管理器功能的一部分)
mod.rs(修改：调整原来的接口实现以支持进程)
pid.rs(新增：进程标识符和内核栈的 Rust 抽象)
processor.rs(新增：处理器管理结构 ``Processor`` ，为上一章任务管理器功能的一部分)
task.rs(修改：支持进程机制的任务控制块)
mod.rs(修改：对于系统调用的实现进行修改以支持进程系统调用)
user(对于用户库 user_lib 进行修改，替换了一套新的测例)
```



- 为了支持基于应用名而不是应用 ID 来查找应用 ELF 可执行文件，从而实现灵活的应用加载，在 `os/build.rs` 以及 `os/src/loader.rs` 中更新了 `link_app.S` 的格式使得它包含每个应用的名字，另外提供 `get_app_data_by_name` 接口获取应用的 ELF 数据。
- 在本章之前，任务管理器 `TaskManager` 不仅负责管理所有的任务状态，还维护着我们的 CPU 当前正在执行哪个任务。这种设计耦合度较高，我们将后一个功能分离到 `os/src/task/processor.rs` 中的处理器管理结构 `Processor` 中，它负责管理 CPU 上执行的任务和一些其他信息；而 `os/src/task/manager.rs` 中的任务管理器 `TaskManager` 仅负责管理所有任务。
- 针对新的进程模型，我们复用前面章节的任务控制块 `TaskControlBlock` 作为进程控制块来保存进程的一些信息，相比前面章节还要新增 PID、内核栈、应用数据大小、父子进程、退出码等信息。它声明在 `os/src/task/task.rs` 中。
- 从本章开始，内核栈在内核地址空间中的位置由所在进程的 PID 决定，我们需要在二者之间建立联系并提供一些相应的资源自动回收机制。可以参考 `os/src/task/pid.rs` 。

Build.rs通过编程的方法生成汇编语言

### 系统调用封装

读者可以在 `user/src/syscall.rs` 中看到以 `sys_*` 开头的系统调用的函数原型，它们后续还会在 `user/src/lib.rs` 中被封装成方便应用程序使用的形式。如 `sys_fork` 被封装成 `fork` ，而 `sys_exec` 被封装成 `exec` 。这里值得一提的是 `sys_waitpid` 被封装成两个不同的 API ：

```
 1// user/src/lib.rs
 2
 3pub fn wait(exit_code: &mut i32) -> isize {
 4    loop {
 5        match sys_waitpid(-1, exit_code as *mut _) {
 6            -2 => { yield_(); }
 7            // -1 or a real pid
 8            exit_pid => return exit_pid,
 9        }
10    }
11}
12
13pub fn waitpid(pid: usize, exit_code: &mut i32) -> isize {
14    loop {
15        match sys_waitpid(pid as isize, exit_code as *mut _) {
16            -2 => { yield_(); }
17            // -1 or a real pid
18            exit_pid => return exit_pid,
19        }
20    }
21}
```

其中 `wait` 表示等待任意一个子进程结束，根据 `sys_waitpid` 的约定它需要传的 pid 参数为 `-1` ；而 `waitpid` 则等待一个 PID 固定的子进程结束。在具体实现方面，我们看到当 `sys_waitpid` 返回值为 `-2` ，即要等待的子进程存在但它却尚未退出的时候，我们调用 `yield_` 主动交出 CPU 使用权，待下次 CPU 使用权被内核交还给它的时候再次调用 `sys_waitpid` 查看要等待的子进程是否退出。这样做可以减小 CPU 资源的浪费。

目前的实现风格是尽可能简化内核，因此 `sys_waitpid` 是立即返回的，即它的返回值只能给出返回这一时刻的状态。如果这一时刻要等待的子进程还尚未结束，那么也只能如实向应用报告这一结果。于是用户库 `user_lib` 就需要负责对返回状态进行持续的监控，因此它里面便需要进行循环检查。在后面的实现中，我们会将 `sys_waitpid` 的内核实现设计为 **阻塞** 的，也即直到得到一个确切的结果位置都停在内核内，也就意味着内核返回给应用的结果可以直接使用。那是 `wait` 和 `waitpid` 两个 API 的实现便会更加简单。

### 用户初始程序-initproc

我们首先来看用户初始程序-initproc是如何实现的：

```
 1// user/src/bin/initproc.rs
 2
 3#![no_std]
 4#![no_main]
 5
 6#[macro_use]
 7extern crate user_lib;
 8
 9use user_lib::{
10    fork,
11    wait,
12    exec,
13    yield_,
14};
15
16#[no_mangle]
17fn main() -> i32 {
18    if fork() == 0 {
19        exec("user_shell\0");
20    } else {
21        loop {
22            let mut exit_code: i32 = 0;
23            let pid = wait(&mut exit_code);
24            if pid == -1 {
25                yield_();
26                continue;
27            }
28            println!(
29                "[initproc] Released a zombie process, pid={}, exit_code={}",
30                pid,
31                exit_code,
32            );
33        }
34    }
35    0
36}
```

- 第 19 行为 `fork` 返回值为 0 的分支，表示子进程，此行直接通过 `exec` 执行shell程序 `user_shell` ，注意我们需要在字符串末尾手动加入 `\0` ，因为 Rust 在将这些字符串连接到只读数据段的时候不会插入 `\0` 。
- 第 21 行开始则为返回值不为 0 的分支，表示调用 `fork` 的用户初始程序-initproc自身。可以看到它在不断循环调用 `wait` 来等待那些被移交到它下面的子进程并回收它们占据的资源。如果回收成功的话则会打印一条报告信息给出被回收子进程的 PID 和返回值；否则就 `yield_` 交出 CPU 资源并在下次轮到它执行的时候再回收看看。这也可以看出，用户初始程序-initproc对于资源的回收并不算及时，但是对于已经退出的僵尸进程，用户初始程序-initproc最终总能够成功回收它们的资源。



### fork 系统调用的实现

在实现 fork 的时候，最为关键且困难的是为子进程创建一个和父进程几乎完全相同的应用地址空间。我们的实现如下：

```
 1// os/src/mm/memory_set.rs
 2
 3impl MapArea {
 4    pub fn from_another(another: &MapArea) -> Self {
 5        Self {
 6            vpn_range: VPNRange::new(
 7                another.vpn_range.get_start(),
 8                another.vpn_range.get_end()
 9            ),
10            data_frames: BTreeMap::new(),
11            map_type: another.map_type,
12            map_perm: another.map_perm,
13        }
14    }
15}
16
17impl MemorySet {
18    pub fn from_existed_user(user_space: &MemorySet) -> MemorySet {
19        let mut memory_set = Self::new_bare();
20        // map trampoline
21        memory_set.map_trampoline();
22        // copy data sections/trap_context/user_stack
23        for area in user_space.areas.iter() {
24            let new_area = MapArea::from_another(area);
25            memory_set.push(new_area, None);
26            // copy data from another space
27            for vpn in area.vpn_range {
28                let src_ppn = user_space.translate(vpn).unwrap().ppn();
29                let dst_ppn = memory_set.translate(vpn).unwrap().ppn();
30                dst_ppn.get_bytes_array().copy_from_slice(src_ppn.get_bytes_array());
31            }
32        }
33        memory_set
34    }
35}
```

这需要对内存管理子模块 `mm` 做一些拓展：

- 第 4 行的 `MapArea::from_another` 可以从一个逻辑段复制得到一个虚拟地址区间、映射方式和权限控制均相同的逻辑段，不同的是由于它还没有真正被映射到物理页帧上，所以 `data_frames` 字段为空。

- 第 18 行的 `MemorySet::from_existed_user` 可以复制一个完全相同的地址空间。首先在第 19 行，我们通过 `new_bare` 新创建一个空的地址空间，并在第 21 行通过 `map_trampoline` 为这个地址空间映射上跳板页面，这是因为我们解析 ELF 创建地址空间的时候，并没有将跳板页作为一个单独的逻辑段插入到地址空间的逻辑段向量 `areas` 中，所以这里需要单独映射上。

  剩下的逻辑段都包含在 `areas` 中。我们遍历原地址空间中的所有逻辑段，将复制之后的逻辑段插入新的地址空间，在插入的时候就已经实际分配了物理页帧了。接着我们遍历逻辑段中的每个虚拟页面，对应完成数据复制，这只需要找出两个地址空间中的虚拟页面各被映射到哪个物理页帧，就可转化为将数据从物理内存中的一个位置复制到另一个位置，使用 `copy_from_slice` 即可轻松实现。

接着，我们实现 `TaskControlBlock::fork` 来从父进程的进程控制块创建一份子进程的控制块：

```
 1// os/src/task/task.rs
 2
 3impl TaskControlBlock {
 4    pub fn fork(self: &Arc<TaskControlBlock>) -> Arc<TaskControlBlock> {
 5        // ---- hold parent PCB lock
 6        let mut parent_inner = self.acquire_inner_lock();
 7        // copy user space(include trap context)
 8        let memory_set = MemorySet::from_existed_user(
 9            &parent_inner.memory_set
10        );
11        let trap_cx_ppn = memory_set
12            .translate(VirtAddr::from(TRAP_CONTEXT).into())
13            .unwrap()
14            .ppn();
15        // alloc a pid and a kernel stack in kernel space
16        let pid_handle = pid_alloc();
17        let kernel_stack = KernelStack::new(&pid_handle);
18        let kernel_stack_top = kernel_stack.get_top();
19        // push a goto_trap_return task_cx on the top of kernel stack
20        let task_cx_ptr = kernel_stack.push_on_top(TaskContext::goto_trap_return());
21        let task_control_block = Arc::new(TaskControlBlock {
22            pid: pid_handle,
23            kernel_stack,
24            inner: Mutex::new(TaskControlBlockInner {
25                trap_cx_ppn,
26                base_size: parent_inner.base_size,
27                task_cx_ptr: task_cx_ptr as usize,
28                task_status: TaskStatus::Ready,
29                memory_set,
30                parent: Some(Arc::downgrade(self)),
31                children: Vec::new(),
32                exit_code: 0,
33            }),
34        });
35        // add child
36        parent_inner.children.push(task_control_block.clone());
37        // modify kernel_sp in trap_cx
38        // **** acquire child PCB lock
39        let trap_cx = task_control_block.acquire_inner_lock().get_trap_cx();
40        // **** release child PCB lock
41        trap_cx.kernel_sp = kernel_stack_top;
42        // return
43        task_control_block
44        // ---- release parent PCB lock
45    }
46}
```

它基本上和新建进程控制块的 `TaskControlBlock::new` 是相同的，但要注意以下几点：

- 子进程的地址空间不是通过解析 ELF 而是通过在第 8 行调用 `MemorySet::from_existed_user` 复制父进程地址空间得到的；
- 第 26 行，我们让子进程和父进程的 `base_size` ，也即应用数据的大小保持一致；
- 在 fork 的时候需要注意父子进程关系的维护。第 30 行我们将父进程的弱引用计数放到子进程的进程控制块中，而在第 36 行我们将子进程插入到父进程的孩子向量 `children` 中。

我们在子进程内核栈上压入一个初始化的任务上下文，使得内核一旦通过任务切换到该进程，就会跳转到 `trap_return` 来进入用户态。而在复制地址空间的时候，子进程的 Trap 上下文也是完全从父进程复制过来的，这可以保证子进程进入用户态和其父进程回到用户态的那一瞬间 CPU 的状态是完全相同的（后面我们会让它们有一点不同从而区分两个进程）。而两个进程的应用数据由于地址空间复制的原因也是完全相同的，这是 fork 语义要求做到的。

在具体实现 `sys_fork` 的时候，我们需要特别注意如何体现父子进程的差异：

```
 1// os/src/syscall/process.rs
 2
 3pub fn sys_fork() -> isize {
 4    let current_task = current_task().unwrap();
 5    let new_task = current_task.fork();
 6    let new_pid = new_task.pid.0;
 7    // modify trap context of new_task, because it returns immediately after switching
 8    let trap_cx = new_task.acquire_inner_lock().get_trap_cx();
 9    // we do not have to move to next instruction since we have done it before
10    // for child process, fork returns 0
11    trap_cx.x[10] = 0;
12    // add new task to scheduler
13    add_task(new_task);
14    new_pid as isize
15}
```

在调用 `syscall` 进行系统调用分发并具体调用 `sys_fork` 之前，我们已经将当前进程 Trap 上下文中的 sepc 向后移动了 4 字节使得它回到用户态之后会从 ecall 的下一条指令开始执行。之后当我们复制地址空间的时候，子进程地址空间 Trap 上下文的 sepc 也是移动之后的值，我们无需再进行修改。

父子进程回到用户态的瞬间都处于刚刚从一次系统调用返回的状态，但二者的返回值不同。第 8~11 行我们将子进程的 Trap 上下文用来存放系统调用返回值的 a0 寄存器修改为 0 ，而父进程系统调用的返回值会在 `trap_handler` 中 `syscall` 返回之后再设置为 `sys_fork` 的返回值，这里我们返回子进程的 PID 。这就做到了父进程 `fork` 的返回值为子进程的 PID ，而子进程的返回值则为 0 。通过返回值是否为 0 可以区分父子进程。

另外，不要忘记在第 13 行，我们将生成的子进程通过 `add_task` 加入到任务管理器中。

### exec 系统调用的实现

`exec` 系统调用使得一个进程能够加载一个新的 ELF 可执行文件替换原有的应用地址空间并开始执行。我们先从进程控制块的层面进行修改：

```
 1// os/src/task/task.rs
 2
 3impl TaskControlBlock {
 4    pub fn exec(&self, elf_data: &[u8]) {
 5        // memory_set with elf program headers/trampoline/trap context/user stack
 6        let (memory_set, user_sp, entry_point) = MemorySet::from_elf(elf_data);
 7        let trap_cx_ppn = memory_set
 8            .translate(VirtAddr::from(TRAP_CONTEXT).into())
 9            .unwrap()
10            .ppn();
11
12        // **** hold current PCB lock
13        let mut inner = self.acquire_inner_lock();
14        // substitute memory_set
15        inner.memory_set = memory_set;
16        // update trap_cx ppn
17        inner.trap_cx_ppn = trap_cx_ppn;
18        // initialize trap_cx
19        let trap_cx = inner.get_trap_cx();
20        *trap_cx = TrapContext::app_init_context(
21            entry_point,
22            user_sp,
23            KERNEL_SPACE.lock().token(),
24            self.kernel_stack.get_top(),
25            trap_handler as usize,
26        );
27        // **** release current PCB lock
28    }
29}
```

它在解析传入的 ELF 格式数据之后只做了两件事情：

- 首先是从 ELF 生成一个全新的地址空间并直接替换进来（第 15 行），这将导致原有的地址空间生命周期结束，里面包含的全部物理页帧都会被回收；
- 然后是修改新的地址空间中的 Trap 上下文，将解析得到的应用入口点、用户栈位置以及一些内核的信息进行初始化，这样才能正常实现 Trap 机制。

这里无需对任务上下文进行处理，因为这个进程本身已经在执行了，而只有被暂停的应用才需要在内核栈上保留一个任务上下文。

借助它 `sys_exec` 就很容易实现了：

```
 1// os/src/mm/page_table.rs
 2
 3pub fn translated_str(token: usize, ptr: *const u8) -> String {
 4    let page_table = PageTable::from_token(token);
 5    let mut string = String::new();
 6    let mut va = ptr as usize;
 7    loop {
 8        let ch: u8 = *(page_table.translate_va(VirtAddr::from(va)).unwrap().get_mut());
 9        if ch == 0 {
10            break;
11        } else {
12            string.push(ch as char);
13            va += 1;
14        }
15    }
16    string
17}
18
19// os/src/syscall/process.rs
20
21pub fn sys_exec(path: *const u8) -> isize {
22    let token = current_user_token();
23    let path = translated_str(token, path);
24    if let Some(data) = get_app_data_by_name(path.as_str()) {
25        let task = current_task().unwrap();
26        task.exec(data);
27        0
28    } else {
29        -1
30    }
31}
```

应用在 `sys_exec` 系统调用中传递给内核的只有一个要执行的应用名字符串在当前应用地址空间中的起始地址，如果想在内核中具体获得字符串的话就需要手动查页表。第 3 行的 `translated_str` 便可以从内核地址空间之外的某个地址空间中拿到一个字符串，其原理就是逐字节查页表直到发现一个 `\0` 为止。

回到 `sys_exec` 的实现，它调用 `translated_str` 找到要执行的应用名并试图在应用加载器提供的 `get_app_data_by_name` 接口中找到对应的 ELF 数据。如果找到的话就调用 `TaskControlBlock::exec` 替换掉地址空间并返回 0。这个返回值其实并没有意义，因为我们在替换地址空间的时候本来就对 Trap 上下文重新进行了初始化。如果没有找到的话就不做任何事情并返回 -1，在shell程序-user_shell中我们也正是通过这个返回值来判断要执行的应用是否存在。

### 系统调用后重新获取 Trap 上下文

原来在 `trap_handler` 中我们是这样处理系统调用的：

```
// os/src/trap/mod.rs

#[no_mangle]
pub fn trap_handler() -> ! {
    set_kernel_trap_entry();
    let cx = current_trap_cx();
    let scause = scause::read();
    let stval = stval::read();
    match scause.cause() {
        Trap::Exception(Exception::UserEnvCall) => {
            cx.sepc += 4;
            cx.x[10] = syscall(cx.x[17], [cx.x[10], cx.x[11], cx.x[12]]) as usize;
        }
        ...
    }
    trap_return();
}
```

这里的 `cx` 是当前应用的 Trap 上下文的可变引用，我们需要通过查页表找到它具体被放在哪个物理页帧上，并构造相同的虚拟地址来在内核中访问它。对于系统调用 `sys_exec` 来说，一旦调用它之后，我们会发现 `trap_handler` 原来上下文中的 `cx` 失效了——因为它是用来访问之前地址空间中 Trap 上下文被保存在的那个物理页帧的，而现在它已经被回收掉了。因此，为了能够处理类似的这种情况，我们在 `syscall` 分发函数返回之后需要重新获取 `cx` ，目前的实现如下：

```
// os/src/trap/mod.rs

#[no_mangle]
pub fn trap_handler() -> ! {
    set_kernel_trap_entry();
    let scause = scause::read();
    let stval = stval::read();
    match scause.cause() {
        Trap::Exception(Exception::UserEnvCall) => {
            // jump to next instruction anyway
            let mut cx = current_trap_cx();
            cx.sepc += 4;
            // get system call return value
            let result = syscall(cx.x[17], [cx.x[10], cx.x[11], cx.x[12]]);
            // cx is changed during sys_exec, so we have to call it again
            cx = current_trap_cx();
            cx.x[10] = result as usize;
        }
        ...
    }
    trap_return();
}
```

```
 1// os/src/mm/memory_set.rs
 2
 3impl MemorySet {
 4    pub fn recycle_data_pages(&mut self) {
 5        self.areas.clear();
 6    }
 7}
 8
 9// os/src/task/mod.rs
10
11pub fn exit_current_and_run_next(exit_code: i32) {
12    // take from Processor
13    let task = take_current_task().unwrap();
14    // **** hold current PCB lock
15    let mut inner = task.acquire_inner_lock();
16    // Change status to Zombie
17    inner.task_status = TaskStatus::Zombie;
18    // Record exit code
19    inner.exit_code = exit_code;
20    // do not move to its parent but under initproc
21
22    // ++++++ hold initproc PCB lock here
23    {
24        let mut initproc_inner = INITPROC.acquire_inner_lock();
25        for child in inner.children.iter() {
26            child.acquire_inner_lock().parent = Some(Arc::downgrade(&INITPROC));
27            initproc_inner.children.push(child.clone());
28        }
29    }
30    // ++++++ release parent PCB lock here
31
32    inner.children.clear();
33    // deallocate user space
34    inner.memory_set.recycle_data_pages();
35    drop(inner);
36    // **** release current PCB lock
37    // drop task manually to maintain rc correctly
38    drop(task);
39    // we do not have to save task context
40    let _unused: usize = 0;
41    schedule(&_unused as *const _);
42}
```

- 第 13 行我们调用 `take_current_task` 来将当前进程控制块从处理器监控 `PROCESSOR` 中取出而不是得到一份拷贝，这是为了正确维护进程控制块的引用计数；
- 第 17 行我们将进程控制块中的状态修改为 `TaskStatus::Zombie` 即僵尸进程，这样它后续才能被父进程在 `waitpid` 系统调用的时候回收；
- 第 19 行我们将传入的退出码 `exit_code` 写入进程控制块中，后续父进程在 `waitpid` 的时候可以收集；
- 第 24~26 行所做的事情是将当前进程的所有子进程挂在初始进程 `initproc` 下面，其做法是遍历每个子进程，修改其父进程为初始进程，并加入初始进程的孩子向量中。第 32 行将当前进程的孩子向量清空。
- 第 34 行对于当前进程占用的资源进行早期回收。在第 4 行可以看出， `MemorySet::recycle_data_pages` 只是将地址空间中的逻辑段列表 `areas` 清空，这将导致应用地址空间的所有数据被存放在的物理页帧被回收，而用来存放页表的那些物理页帧此时则不会被回收。
- 最后在第 41 行我们调用 `schedule` 触发调度及任务切换，由于我们再也不会回到该进程的执行过程中，因此无需关心任务上下文的保存。

### 父进程回收子进程资源

父进程通过 `sys_waitpid` 系统调用来回收子进程的资源并收集它的一些信息：

```
 1// os/src/syscall/process.rs
 2
 3/// If there is not a child process whose pid is same as given, return -1.
 4/// Else if there is a child process but it is still running, return -2.
 5pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
 6    let task = current_task().unwrap();
 7    // find a child process
 8
 9    // ---- hold current PCB lock
10    let mut inner = task.acquire_inner_lock();
11    if inner.children
12        .iter()
13        .find(|p| {pid == -1 || pid as usize == p.getpid()})
14        .is_none() {
15        return -1;
16        // ---- release current PCB lock
17    }
18    let pair = inner.children
19        .iter()
20        .enumerate()
21        .find(|(_, p)| {
22            // ++++ temporarily hold child PCB lock
23            p.acquire_inner_lock().is_zombie() &&
24            (pid == -1 || pid as usize == p.getpid())
25            // ++++ release child PCB lock
26        });
27    if let Some((idx, _)) = pair {
28        let child = inner.children.remove(idx);
29        // confirm that child will be deallocated after removing from children list
30        assert_eq!(Arc::strong_count(&child), 1);
31        let found_pid = child.getpid();
32        // ++++ temporarily hold child lock
33        let exit_code = child.acquire_inner_lock().exit_code;
34        // ++++ release child PCB lock
35        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
36        found_pid as isize
37    } else {
38        -2
39    }
40    // ---- release current PCB lock automatically
41}
```

`sys_waitpid` 是一个立即返回的系统调用，它的返回值语义是：如果当前的进程不存在一个符合要求的子进程，则返回 -1；如果至少存在一个，但是其中没有僵尸进程（也即仍未退出）则返回 -2；如果都不是的话则可以正常回收并返回回收子进程的 pid 。但在编写应用的开发者看来， `wait/waitpid` 两个辅助函数都必定能够返回一个有意义的结果，要么是 -1，要么是一个正数 PID ，是不存在 -2 这种通过等待即可消除的中间结果的。这等待的过程正是在用户库 `user_lib` 中完成。

第 11~17 行判断 `sys_waitpid` 是否会返回 -1 ，这取决于当前进程是否有一个符合要求的子进程。当传入的 `pid` 为 -1 的时候，任何一个子进程都算是符合要求；但 `pid` 不为 -1 的时候，则只有 PID 恰好与 `pid` 相同的子进程才算符合条件。我们简单通过迭代器即可完成判断。

第 18~26 行判断符合要求的子进程中是否有僵尸进程，如果有的话还需要同时找出它在当前进程控制块子进程向量中的下标。如果找不到的话直接返回 `-2` ，否则进入第 28~36 行的处理：

- 第 28 行我们将子进程从向量中移除并置于当前上下文中，此时可以确认这是对于该子进程控制块的唯一一次强引用，即它不会出现在某个进程的子进程向量中，更不会出现在处理器监控器或者任务管理器中。当它所在的代码块结束，这次引用变量的生命周期结束，将导致该子进程进程控制块的引用计数变为 0 ，彻底回收掉它占用的所有资源，包括：内核栈和它的 PID 还有它的应用地址空间存放页表的那些物理页帧等等。
- 剩下主要是将收集的子进程信息返回回去。第 31 行得到了子进程的 PID 并会在最终返回；第 33 行得到了子进程的退出码并于第 35 行写入到当前进程的应用地址空间中。由于应用传递给内核的仅仅是一个指向应用地址空间中保存子进程返回值的内存区域的指针，我们还需要在 `translated_refmut` 中手动查页表找到应该写入到物理内存中的哪个位置。其实现可以在 `os/src/mm/page_table.rs` 中找到，比较简单，在这里不再赘述。

## 第六章：进程间通信

File trait

```rust
pub trait File : Send + Sync {
    fn read(&self, buf: UserBuffer) -> usize;
    fn write(&self, buf: UserBuffer) -> usize;
}
```

其中 `UserBuffer` 是我们在 `mm` 子模块中定义的应用地址空间中的一段缓冲区（即内存）的抽象。它本质上其实只是一个 `&[u8]` ，但是它位于应用地址空间中，在内核中我们无法直接通过这种方式来访问，因此需要进行封装。然而，在理解抽象接口 `File` 的各方法时，我们仍可以将 `UserBuffer` 看成一个 `&[u8]` 切片，它是同时给出了缓冲区的起始地址及长度的一个胖指针。

```rust
 1// os/src/task/task.rs
 2
 3pub struct TaskControlBlockInner {
 4    pub trap_cx_ppn: PhysPageNum,
 5    pub base_size: usize,
 6    pub task_cx_ptr: usize,
 7    pub task_status: TaskStatus,
 8    pub memory_set: MemorySet,
 9    pub parent: Option<Weak<TaskControlBlock>>,
10    pub children: Vec<Arc<TaskControlBlock>>,
11    pub exit_code: i32,
12    pub fd_table: Vec<Option<Arc<dyn File + Send + Sync>>>,
13}
```

其中新增加		pub fd_table: Vec<Option<Arc<dyn File + Send + Sync>>>   文件描述符表

以看到 `fd_table` 的类型包含多层嵌套，我们从外到里分别说明：

- `Vec` 的动态长度特性使得我们无需设置一个固定的文件描述符数量上限，我们可以更加灵活的使用内存，而不必操心内存管理问题；
- `Option` 使得我们可以区分一个文件描述符当前是否空闲，当它是 `None` 的时候是空闲的，而 `Some` 则代表它已被占用；
- `Arc` 首先提供了共享引用能力。后面我们会提到，可能会有多个进程共享同一个文件对它进行读写。此外被它包裹的内容会被放到内核堆而不是栈上，于是它便不需要在编译期有着确定的大小；
- `dyn` 关键字表明 `Arc` 里面的类型实现了 `File/Send/Sync` 三个 Trait ，但是编译期无法知道它具体是哪个类型（可能是任何实现了 `File` Trait 的类型如 `Stdin/Stdout` ，故而它所占的空间大小自然也无法确定），需要等到运行时才能知道它的具体类型，对于一些抽象方法的调用也是在那个时候才能找到该类型实现的版本的地址并跳转过去。

注解

**Rust 语法卡片：Rust 中的多态**

在编程语言中， **多态** (Polymorphism) 指的是在同一段代码中可以隐含多种不同类型的特征。**在 Rust 中主要通过泛型和 Trait 来实现多态**。

泛型是一种 **编译期多态** (Static Polymorphism)，在编译一个泛型函数的时候，编译器会对于所有可能用到的类型进行实例化并对应生成一个版本的汇编代码，在编译期就能知道选取哪个版本并确定函数地址，这可能会导致生成的二进制文件体积较大；**而 Trait 对象（也即上面提到的 `dyn` 语法）是一种 运行时多态 (Dynamic Polymorphism)，需要在运行时查一种类似于 C++ 中的 虚表 (Virtual Table) 才能找到实际类型对于抽象接口实现的函数地址并进行调用，这样会带来一定的运行时开销，但是更为灵活**。

所以在创建TCB的时候默认为每个进程打开 stdin stdout   *stderr

## 第七章：文件系统于I/O重定向



### 文件打开

在读写一个常规文件之前，应用首先需要通过内核提供的 `sys_open` 系统调用让该文件在进程的文件描述符表中占一项，并得到操作系统的返回值–文件描述符，即文件关联的表项在文件描述表中的索引值：

```
/// 功能：打开一个常规文件，并返回可以访问它的文件描述符。
/// 参数：path 描述要打开的文件的文件名（简单起见，文件系统不需要支持目录，所有的文件都放在根目录 / 下），
/// flags 描述打开文件的标志，具体含义下面给出。
/// 返回值：如果出现了错误则返回 -1，否则返回打开常规文件的文件描述符。可能的错误原因是：文件不存在。
/// syscall ID：56
pub fn sys_open(path: *const u8, flags: u32) -> isize;
```

目前我们的内核支持以下几种标志（多种不同标志可能共存）：

- 如果 `flags` 为 0，则表示以只读模式 *RDONLY* 打开；
- 如果 `flags` 第 0 位被设置（0x001），表示以只写模式 *WRONLY* 打开；
- 如果 `flags` 第 1 位被设置（0x002），表示既可读又可写 *RDWR* ；
- 如果 `flags` 第 9 位被设置（0x200），表示允许创建文件 *CREATE* ，在找不到该文件的时候应创建文件；如果该文件已经存在则应该将该文件的大小归零；
- 如果 `flags` 第 10 位被设置（0x400），则在打开文件的时候应该清空文件的内容并将该文件的大小归零，也即 *TRUNC* 。

注意 `flags` 里面的权限设置只能控制进程对本次打开的文件的访问。一般情况下，在打开文件的时候首先需要经过文件系统的权限检查，比如一个文件自身不允许写入，那么进程自然也就不能以 *WRONLY* 或 *RDWR* 标志打开文件。但在我们简化版的文件系统中文件不进行权限设置，这一步就可以绕过。

在用户库 `user_lib` 中，我们将该系统调用封装为 `open` 接口：

```
// user/src/lib.rs

bitflags! {
    pub struct OpenFlags: u32 {
        const RDONLY = 0;
        const WRONLY = 1 << 0;
        const RDWR = 1 << 1;
        const CREATE = 1 << 9;
        const TRUNC = 1 << 10;
    }
}

pub fn open(path: &str, flags: OpenFlags) -> isize {
    sys_open(path, flags.bits)
}
```

借助 `bitflags!` 宏我们将一个 `u32` 的 flags 包装为一个 `OpenFlags` 结构体更易使用，它的 `bits` 字段可以将自身转回 `u32` ，它也会被传给 `sys_open` ：

```
// user/src/syscall.rs

const SYSCALL_OPEN: usize = 56;

pub fn sys_open(path: &str, flags: u32) -> isize {
    syscall(SYSCALL_OPEN, [path.as_ptr() as usize, flags as usize, 0])
}
```

我们在 `sys_open` 传给内核的两个参数只有待打开文件的文件名字符串的起始地址（和之前一样，我们需要保证该字符串以 `\0` 结尾）还有标志位。由于每个通用寄存器为 64 位，我们需要先将 `u32` 的 `flags` 转换为 `usize` 。

### 简易文件系统

**内存映射 I/O** (MMIO, Memory-Mapped I/O) 指的是外设的设备寄存器可以通过特定的物理内存地址来访问，每个外设的设备寄存器都分布在没有交集的一个或数个物理地址区间中，不同外设的设备寄存器所占的物理地址空间也不会产生交集，且这些外设物理地址区间也不会和RAM的物理内存所在的区间存在交集。从 RV64 平台 Qemu 的 [源码](https://github.com/qemu/qemu/blob/master/hw/riscv/virt.c#L58) 中可以找到 VirtIO 总线的 MMIO 物理地址区间为从 0x10001000 开头的 4KiB 。为了能够在内核中访问 VirtIO 总线，我们就必须在内核地址空间中对特定内存区域提前进行映射：

```
// os/src/config.rs

#[cfg(feature = "board_qemu")]
pub const MMIO: &[(usize, usize)] = &[
    (0x10001000, 0x1000),
];
```

如上面一段代码所示，在 `config` 子模块中我们硬编码 Qemu 上的 VirtIO 总线的 MMIO 地址区间（起始地址，长度）。在创建内核地址空间的时候需要建立页表映射：

```
// os/src/mm/memory_set.rs

use crate::config::MMIO;

impl MemorySet {
    /// Without kernel stacks.
    pub fn new_kernel() -> Self {
        ...
        println!("mapping memory-mapped registers");
        for pair in MMIO {
            memory_set.push(MapArea::new(
                (*pair).0.into(),
                ((*pair).0 + (*pair).1).into(),
                MapType::Identical,
                MapPermission::R | MapPermission::W,
            ), None);
        }
        memory_set
    }
}
```

这里我们进行的是透明的恒等映射，从而让内核可以兼容于直接访问物理地址的设备驱动库。

由于设备驱动的开发过程比较琐碎，我们这里直接使用已有的 [virtio-drivers](https://github.com/rcore-os/virtio-drivers) crate ，它已经支持 VirtIO 总线架构下的块设备、网络设备、GPU 等设备。关于VirtIO 相关驱动的内容，将放在后续章节中介绍。

```
// os/src/drivers/block/virtio_blk.rs

use virtio_drivers::{VirtIOBlk, VirtIOHeader};
const VIRTIO0: usize = 0x10001000;

pub struct VirtIOBlock(Mutex<VirtIOBlk<'static>>);

impl VirtIOBlock {
    pub fn new() -> Self {
        Self(Mutex::new(VirtIOBlk::new(
            unsafe { &mut *(VIRTIO0 as *mut VirtIOHeader) }
        ).unwrap()))
    }
}

impl BlockDevice for VirtIOBlock {
    fn read_block(&self, block_id: usize, buf: &mut [u8]) {
        self.0.lock().read_block(block_id, buf).expect("Error when reading VirtIOBlk");
    }
    fn write_block(&self, block_id: usize, buf: &[u8]) {
        self.0.lock().write_block(block_id, buf).expect("Error when writing VirtIOBlk");
    }
}
```

上面的代码中，我们将 `virtio-drivers` crate 提供的 VirtIO 块设备抽象 `VirtIOBlk` 包装为我们自己的 `VirtIOBlock` ，实质上只是加上了一层互斥锁，生成一个新的类型来实现 `easy-fs` 需要的 `BlockDevice` Trait 。注意在 `VirtIOBlk::new` 的时候需要传入一个 `&mut VirtIOHeader` 的参数， `VirtIOHeader` 实际上就代表以 MMIO 方式访问 VirtIO 设备所需的一组设备寄存器。因此我们从 `qemu-system-riscv64` 平台上的 Virtio MMIO 区间左端 `VIRTIO0` 开始转化为一个 `&mut VirtIOHeader` 就可以在该平台上访问这些设备寄存器了。

很容易为 `VirtIOBlock` 实现 `BlockDevice` Trait ，因为它内部来自 `virtio-drivers` crate 的 `VirtIOBlk` 类型已经实现了 `read/write_block` 方法，我们进行转发即可。

VirtIO 设备需要占用部分内存作为一个公共区域从而更好的和 CPU 进行合作。这就像 MMU 需要在内存中保存多级页表才能和 CPU 共同实现分页机制一样。在 VirtIO 架构下，需要在公共区域中放置一种叫做 VirtQueue 的环形队列，CPU 可以向此环形队列中向 VirtIO 设备提交请求，也可以从队列中取得请求的结果，详情可以参考 [virtio 文档](https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.pdf) 。对于 VirtQueue 的使用涉及到物理内存的分配和回收，但这并不在 VirtIO 驱动 `virtio-drivers` 的职责范围之内，因此它声明了数个相关的接口，需要库的使用者自己来实现：

```
// https://github.com/rcore-os/virtio-drivers/blob/master/src/hal.rs#L57

extern "C" {
    fn virtio_dma_alloc(pages: usize) -> PhysAddr;
    fn virtio_dma_dealloc(paddr: PhysAddr, pages: usize) -> i32;
    fn virtio_phys_to_virt(paddr: PhysAddr) -> VirtAddr;
    fn virtio_virt_to_phys(vaddr: VirtAddr) -> PhysAddr;
}
```

由于我们已经实现了基于分页内存管理的地址空间，实现这些功能自然不在话下：

```
// os/src/drivers/block/virtio_blk.rs

lazy_static! {
    static ref QUEUE_FRAMES: Mutex<Vec<FrameTracker>> = Mutex::new(Vec::new());
}

#[no_mangle]
pub extern "C" fn virtio_dma_alloc(pages: usize) -> PhysAddr {
    let mut ppn_base = PhysPageNum(0);
    for i in 0..pages {
        let frame = frame_alloc().unwrap();
        if i == 0 { ppn_base = frame.ppn; }
        assert_eq!(frame.ppn.0, ppn_base.0 + i);
        QUEUE_FRAMES.lock().push(frame);
    }
    ppn_base.into()
}

#[no_mangle]
pub extern "C" fn virtio_dma_dealloc(pa: PhysAddr, pages: usize) -> i32 {
    let mut ppn_base: PhysPageNum = pa.into();
    for _ in 0..pages {
        frame_dealloc(ppn_base);
        ppn_base.step();
    }
    0
}

#[no_mangle]
pub extern "C" fn virtio_phys_to_virt(paddr: PhysAddr) -> VirtAddr {
    VirtAddr(paddr.0)
}

#[no_mangle]
pub extern "C" fn virtio_virt_to_phys(vaddr: VirtAddr) -> PhysAddr {
    PageTable::from_token(kernel_token()).translate_va(vaddr).unwrap()
}
```

这里有一些细节需要注意：

- `virtio_dma_alloc/dealloc` 需要分配/回收数个 *连续* 的物理页帧，而我们的 `frame_alloc` 是逐个分配，严格来说并不保证分配的连续性。幸运的是，这个过程只会发生在内核初始化阶段，因此能够保证连续性。
- 在 `virtio_dma_alloc` 中通过 `frame_alloc` 得到的那些物理页帧 `FrameTracker` 都会被保存在全局的向量 `QUEUE_FRAMES` 以延长它们的生命周期，避免提前被回收。



### shell程序的命令行参数分割

回忆一下，之前在shell程序 `user_shell` 中，一旦接收到一个回车，我们就会将当前行的内容 `line` 作为一个名字并试图去执行同名的应用。但是现在 `line` 还可能包含一些命令行参数，只有最开头的一个才是要执行的应用名。因此我们要做的第一件事情就是将 `line` 用空格进行分割：

```
// user/src/bin/user_shell.rs

let args: Vec<_> = line.as_str().split(' ').collect();
let mut args_copy: Vec<String> = args
.iter()
.map(|&arg| {
    let mut string = String::new();
    string.push_str(arg);
    string
})
.collect();

args_copy
.iter_mut()
.for_each(|string| {
    string.push('\0');
});
```

经过分割， `args` 中的 `&str` 都是 `line` 中的一段子区间，它们的结尾并没有包含 `\0` ，因为 `line` 是我们输入得到的，中间本来就没有 `\0` 。由于在向内核传入字符串的时候，我们只能传入字符串的起始地址，因此我们必须保证其结尾为 `\0` 。从而我们用 `args_copy` 将 `args` 中的字符串拷贝一份到堆上并在末尾手动加入 `\0` 。这样就可以安心的将 `args_copy` 中的字符串传入内核了。我们用 `args_addr` 来收集这些字符串的起始地址：

```
// user/src/bin/user_shell.rs

let mut args_addr: Vec<*const u8> = args_copy
.iter()
.map(|arg| arg.as_ptr())
.collect();
args_addr.push(0 as *const u8);
```

向量 `args_addr` 中的每个元素都代表一个命令行参数字符串的起始地址。由于我们要传递给内核的是这个向量的起始地址，为了让内核能够获取到命令行参数的个数，我们需要在 `args_addr` 的末尾放入一个 0 ，这样内核看到它的时候就能知道命令行参数已经获取完毕了。

在 `fork` 出来的子进程里面我们需要这样执行应用：

```
// user/src/bin/user_shell.rs

// child process
if exec(args_copy[0].as_str(), args_addr.as_slice()) == -1 {
    println!("Error when executing!");
    return -4;
}
```

### sys_exec 将命令行参数压入用户栈

在 `sys_exec` 中，首先需要将应用传进来的命令行参数取出来：

```
 1// os/src/syscall/process.rs
 2
 3pub fn sys_exec(path: *const u8, mut args: *const usize) -> isize {
 4    let token = current_user_token();
 5    let path = translated_str(token, path);
 6    let mut args_vec: Vec<String> = Vec::new();
 7    loop {
 8        let arg_str_ptr = *translated_ref(token, args);
 9        if arg_str_ptr == 0 {
10            break;
11        }
12        args_vec.push(translated_str(token, arg_str_ptr as *const u8));
13        unsafe { args = args.add(1); }
14    }
15    if let Some(app_inode) = open_file(path.as_str(), OpenFlags::RDONLY) {
16        let all_data = app_inode.read_all();
17        let task = current_task().unwrap();
18        let argc = args_vec.len();
19        task.exec(all_data.as_slice(), args_vec);
20        // return argc because cx.x[10] will be covered with it later
21        argc as isize
22    } else {
23        -1
24    }
25}
```

这里的 `args` 指向命令行参数字符串起始地址数组中的一个位置，每次我们都可以从一个起始地址通过 `translated_str` 拿到一个字符串，直到 `args` 为 0 就说明没有更多命令行参数了。在第 19 行调用 `TaskControlBlock::exec` 的时候，我们需要将获取到的 `args_vec` 传入进去并将里面的字符串压入到用户栈上。

```
 1// os/src/task/task.rs
 2
 3impl TaskControlBlock {
 4    pub fn exec(&self, elf_data: &[u8], args: Vec<String>) {
 5        // memory_set with elf program headers/trampoline/trap context/user stack
 6        let (memory_set, mut user_sp, entry_point) = MemorySet::from_elf(elf_data);
 7        let trap_cx_ppn = memory_set
 8            .translate(VirtAddr::from(TRAP_CONTEXT).into())
 9            .unwrap()
10            .ppn();
11        // push arguments on user stack
12        user_sp -= (args.len() + 1) * core::mem::size_of::<usize>();
13        let argv_base = user_sp;
14        let mut argv: Vec<_> = (0..=args.len())
15            .map(|arg| {
16                translated_refmut(
17                    memory_set.token(),
18                    (argv_base + arg * core::mem::size_of::<usize>()) as *mut usize
19                )
20            })
21            .collect();
22        *argv[args.len()] = 0;
23        for i in 0..args.len() {
24            user_sp -= args[i].len() + 1;
25            *argv[i] = user_sp;
26            let mut p = user_sp;
27            for c in args[i].as_bytes() {
28                *translated_refmut(memory_set.token(), p as *mut u8) = *c;
29                p += 1;
30            }
31            *translated_refmut(memory_set.token(), p as *mut u8) = 0;
32        }
33        // make the user_sp aligned to 8B for k210 platform
34        user_sp -= user_sp % core::mem::size_of::<usize>();
35
36        // **** hold current PCB lock
37        let mut inner = self.acquire_inner_lock();
38        // substitute memory_set
39        inner.memory_set = memory_set;
40        // update trap_cx ppn
41        inner.trap_cx_ppn = trap_cx_ppn;
42        // initialize trap_cx
43        let mut trap_cx = TrapContext::app_init_context(
44            entry_point,
45            user_sp,
46            KERNEL_SPACE.lock().token(),
47            self.kernel_stack.get_top(),
48            trap_handler as usize,
49        );
50        trap_cx.x[10] = args.len();
51        trap_cx.x[11] = argv_base;
52        *inner.get_trap_cx() = trap_cx;
53        // **** release current PCB lock
54    }
55}
```

第 11-34 行所做的主要工作是将命令行参数以某种格式压入用户栈。具体的格式可以参考下图（比如应用传入了两个命令行参数 `aa` 和 `bb` ）

![](https://pic.imgdb.cn/item/60ff748f5132923bf82e0a04.png)



最后涉及[命令行参数与标准 I/O 重定向 — rCore-Tutorial-Book-v3 0.1 文档 (rcore-os.github.io)](https://rcore-os.github.io/rCore-Tutorial-Book-v3/chapter7/4cmdargs-and-redirection.html)

直接跳转学习

剩下的都在流程图里





虚拟磁盘 ：链接：https://pan.baidu.com/s/1SwXLCvOoRBrcgZ8GvajrjA 
提取码：yjk2





