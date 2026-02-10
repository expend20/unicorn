#include "unicorn_test.h"

const uint64_t code_start = 0x1000;
const uint64_t code_len = 0x4000;

#define MEM_BASE 0x40000000
#define MEM_SIZE 1024 * 1024
#define MEM_STACK MEM_BASE + (MEM_SIZE / 2)
#define MEM_TEXT MEM_STACK + 4096

static void uc_common_setup(uc_engine **uc, uc_arch arch, uc_mode mode,
                            const char *code, uint64_t size)
{
    OK(uc_open(arch, mode, uc));
    OK(uc_mem_map(*uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(*uc, code_start, code, size));
}

typedef struct RegInfo_t {
    const char *file;
    int line;
    const char *name;
    uc_x86_reg reg;
    uint64_t value;
} RegInfo;

typedef struct QuickTest_t {
    uc_mode mode;
    uint8_t *code_data;
    size_t code_size;
    size_t in_count;
    RegInfo in_regs[32];
    size_t out_count;
    RegInfo out_regs[32];
} QuickTest;

static void QuickTest_run(QuickTest *test)
{
    uc_engine *uc;

    // initialize emulator in X86-64bit mode
    OK(uc_open(UC_ARCH_X86, test->mode, &uc));

    // map 1MB of memory for this emulation
    OK(uc_mem_map(uc, MEM_BASE, MEM_SIZE, UC_PROT_ALL));
    OK(uc_mem_write(uc, MEM_TEXT, test->code_data, test->code_size));
    if (test->mode == UC_MODE_64) {
        uint64_t stack_top = MEM_STACK;
        OK(uc_reg_write(uc, UC_X86_REG_RSP, &stack_top));
    } else {
        uint32_t stack_top = MEM_STACK;
        OK(uc_reg_write(uc, UC_X86_REG_ESP, &stack_top));
    }
    for (size_t i = 0; i < test->in_count; i++) {
        if (test->mode == UC_MODE_64) {
            OK(uc_reg_write(uc, test->in_regs[i].reg, &test->in_regs[i].value));
        } else {
            uint32_t reg = test->in_regs[i].value & 0xFFFFFFFF;
            OK(uc_reg_write(uc, test->in_regs[i].reg, &reg));
        }
    }
    OK(uc_emu_start(uc, MEM_TEXT, MEM_TEXT + test->code_size, 0, 0));
    for (size_t i = 0; i < test->out_count; i++) {
        RegInfo *out = &test->out_regs[i];
        if (test->mode == UC_MODE_64) {
            uint64_t value = 0;
            OK(uc_reg_read(uc, out->reg, &value));
            acutest_check_(value == out->value, out->file, out->line,
                           "OUT_REG(%s, 0x%" PRIx64 ") = 0x%" PRIx64 "",
                           out->name, out->value, value);
        } else {
            uint32_t value = 0;
            OK(uc_reg_read(uc, out->reg, &value));
            acutest_check_(value == (uint32_t)out->value, out->file, out->line,
                           "OUT_REG(%s, 0x%X) = 0x%X", out->name,
                           (uint32_t)out->value, value);
        }
    }
    OK(uc_mem_unmap(uc, MEM_BASE, MEM_SIZE));
    OK(uc_close(uc));
}

#define TEST_CODE(MODE, CODE)                                                  \
    QuickTest t;                                                               \
    memset(&t, 0, sizeof(t));                                                  \
    t.mode = MODE;                                                             \
    t.code_data = CODE;                                                        \
    t.code_size = sizeof(CODE)

#define TEST_IN_REG(NAME, VALUE)                                               \
    t.in_regs[t.in_count].file = __FILE__;                                     \
    t.in_regs[t.in_count].line = __LINE__;                                     \
    t.in_regs[t.in_count].name = #NAME;                                        \
    t.in_regs[t.in_count].reg = UC_X86_REG_##NAME;                             \
    t.in_regs[t.in_count].value = VALUE;                                       \
    t.in_count++

#define TEST_OUT_REG(NAME, VALUE)                                              \
    t.out_regs[t.out_count].file = __FILE__;                                   \
    t.out_regs[t.out_count].line = __LINE__;                                   \
    t.out_regs[t.out_count].name = #NAME;                                      \
    t.out_regs[t.out_count].reg = UC_X86_REG_##NAME;                           \
    t.out_regs[t.out_count].value = VALUE;                                     \
    t.out_count++

#define TEST_RUN() QuickTest_run(&t)

typedef struct _INSN_IN_RESULT {
    uint32_t port;
    int size;
} INSN_IN_RESULT;

static void test_x86_in_callback(uc_engine *uc, uint32_t port, int size,
                                 void *user_data)
{
    INSN_IN_RESULT *result = (INSN_IN_RESULT *)user_data;
    uint32_t eip;

    result->port = port;
    result->size = size;

    OK(uc_reg_read(uc, UC_X86_REG_EIP, (void*)&eip));
    TEST_CHECK(eip == code_start);
}

static void test_x86_in(void)
{
    uc_engine *uc;
    uc_hook hook;
    char code[] = "\xe5\x10"; // IN eax, 0x10
    INSN_IN_RESULT result;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_hook_add(uc, &hook, UC_HOOK_INSN, test_x86_in_callback, &result, 1, 0,
                   UC_X86_INS_IN));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    TEST_CHECK(result.port == 0x10);
    TEST_CHECK(result.size == 4);

    OK(uc_hook_del(uc, hook));
    OK(uc_close(uc));
}

typedef struct _INSN_OUT_RESULT {
    uint32_t port;
    int size;
    uint32_t value;
} INSN_OUT_RESULT;

static void test_x86_out_callback(uc_engine *uc, uint32_t port, int size,
                                  uint32_t value, void *user_data)
{
    INSN_OUT_RESULT *result = (INSN_OUT_RESULT *)user_data;

    result->port = port;
    result->size = size;
    result->value = value;
}

static void test_x86_out(void)
{
    uc_engine *uc;
    uc_hook hook;
    char code[] = "\xb0\x32\xe6\x46"; // MOV al, 0x32; OUT  0x46, al;
    INSN_OUT_RESULT result;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_hook_add(uc, &hook, UC_HOOK_INSN, test_x86_out_callback, &result, 1,
                   0, UC_X86_INS_OUT));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    TEST_CHECK(result.port == 0x46);
    TEST_CHECK(result.size == 1);
    TEST_CHECK(result.value == 0x32);

    OK(uc_hook_del(uc, hook));
    OK(uc_close(uc));
}

typedef struct _MEM_HOOK_RESULT {
    uc_mem_type type;
    uint64_t address;
    int size;
    uint64_t value;
} MEM_HOOK_RESULT;

typedef struct _MEM_HOOK_RESULTS {
    uint64_t count;
    MEM_HOOK_RESULT results[16];
} MEM_HOOK_RESULTS;

static bool test_x86_mem_hook_all_callback(uc_engine *uc, uc_mem_type type,
                                           uint64_t address, int size,
                                           uint64_t value, void *user_data)
{
    MEM_HOOK_RESULTS *r = (MEM_HOOK_RESULTS *)user_data;
    uint64_t count = r->count;

    if (count >= 16) {
        TEST_ASSERT(false);
    }

    r->results[count].type = type;
    r->results[count].address = address;
    r->results[count].size = size;
    r->results[count].value = value;
    r->count++;

    if (type == UC_MEM_READ_UNMAPPED) {
        uc_mem_map(uc, address, 0x1000, UC_PROT_ALL);
    }

    return true;
}

static void test_x86_mem_hook_all(void)
{
    uc_engine *uc;
    uc_hook hook;
    // mov eax, 0xdeadbeef;
    // mov [0x8000], eax;
    // mov eax, [0x10000];
    char code[] =
        "\xb8\xef\xbe\xad\xde\xa3\x00\x80\x00\x00\xa1\x00\x00\x01\x00";
    MEM_HOOK_RESULTS r = {0};
    MEM_HOOK_RESULT expects[3] = {{UC_MEM_WRITE, 0x8000, 4, 0xdeadbeef},
                                  {UC_MEM_READ_UNMAPPED, 0x10000, 4, 0},
                                  {UC_MEM_READ, 0x10000, 4, 0}};

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_mem_map(uc, 0x8000, 0x1000, UC_PROT_ALL));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_VALID | UC_HOOK_MEM_INVALID,
                   test_x86_mem_hook_all_callback, &r, 1, 0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    TEST_CHECK(r.count == 3);
    for (int i = 0; i < r.count; i++) {
        TEST_CHECK(expects[i].type == r.results[i].type);
        TEST_CHECK(expects[i].address == r.results[i].address);
        TEST_CHECK(expects[i].size == r.results[i].size);
        TEST_CHECK(expects[i].value == r.results[i].value);
    }

    OK(uc_hook_del(uc, hook));
    OK(uc_close(uc));
}

static void test_x86_inc_dec_pxor(void)
{
    uc_engine *uc;
    char code[] =
        "\x41\x4a\x66\x0f\xef\xc1"; // INC ecx; DEC edx; PXOR xmm0, xmm1
    int r_ecx = 0x1234;
    int r_edx = 0x7890;
    uint64_t r_xmm0[2] = {0x08090a0b0c0d0e0f, 0x0001020304050607};
    uint64_t r_xmm1[2] = {0x8090a0b0c0d0e0f0, 0x0010203040506070};

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_X86_HASWELL));
    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code) - 1));

    OK(uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &r_edx));
    OK(uc_reg_write(uc, UC_X86_REG_XMM0, &r_xmm0));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, &r_xmm1));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_read(uc, UC_X86_REG_EDX, &r_edx));
    OK(uc_reg_read(uc, UC_X86_REG_XMM0, &r_xmm0));

    TEST_CHECK(r_ecx == 0x1235);
    TEST_CHECK(r_edx == 0x788f);
    TEST_CHECK(r_xmm0[0] == 0x8899aabbccddeeff);
    TEST_CHECK(r_xmm0[1] == 0x0011223344556677);

    OK(uc_close(uc));
}

static void test_x86_relative_jump(void)
{
    uc_engine *uc;
    char code[] = "\xeb\x02\x90\x90\x90\x90\x90\x90"; // jmp 4; nop; nop; nop;
                                                      // nop; nop; nop
    int r_eip;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);

    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_EIP, &r_eip));

    TEST_CHECK(r_eip == code_start + 4);

    OK(uc_close(uc));
}

static void test_x86_loop(void)
{
    uc_engine *uc;
    char code[] = "\x41\x4a\xeb\xfe"; // inc ecx; dec edx; jmp $;
    int r_ecx = 0x1234;
    int r_edx = 0x7890;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &r_edx));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 1 * 1000000,
                    0));

    OK(uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_read(uc, UC_X86_REG_EDX, &r_edx));

    TEST_CHECK(r_ecx == 0x1235);
    TEST_CHECK(r_edx == 0x788f);

    OK(uc_close(uc));
}

static void test_x86_invalid_mem_read(void)
{
    uc_engine *uc;
    char code[] = "\x8b\x0d\xaa\xaa\xaa\xaa"; // mov  ecx, [0xAAAAAAAA]

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);

    uc_assert_err(
        UC_ERR_READ_UNMAPPED,
        uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_close(uc));
}

static void test_x86_invalid_mem_write(void)
{
    uc_engine *uc;
    char code[] = "\x89\x0d\xaa\xaa\xaa\xaa"; // mov  ecx, [0xAAAAAAAA]

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);

    uc_assert_err(
        UC_ERR_WRITE_UNMAPPED,
        uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_close(uc));
}

static void test_x86_invalid_jump(void)
{
    uc_engine *uc;
    char code[] = "\xe9\xe9\xee\xee\xee"; // jmp 0xEEEEEEEE

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);

    uc_assert_err(
        UC_ERR_FETCH_UNMAPPED,
        uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_close(uc));
}

static void test_x86_64_syscall_callback(uc_engine *uc, void *user_data)
{
    uint64_t rax;

    OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));

    TEST_CHECK(rax == 0x100);
}

static void test_x86_64_syscall(void)
{
    uc_engine *uc;
    uc_hook hook;
    char code[] = "\x0f\x05"; // syscall
    uint64_t r_rax = 0x100;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &r_rax));
    OK(uc_hook_add(uc, &hook, UC_HOOK_INSN, test_x86_64_syscall_callback, NULL,
                   1, 0, UC_X86_INS_SYSCALL));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_hook_del(uc, hook));
    OK(uc_close(uc));
}

static void test_x86_16_add(void)
{
    uc_engine *uc;
    char code[] = "\x00\x00"; // add   byte ptr [bx + si], al
    uint16_t r_ax = 7;
    uint16_t r_bx = 5;
    uint16_t r_si = 6;
    uint8_t result;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_16, code, sizeof(code) - 1);
    OK(uc_mem_map(uc, 0, 0x1000, UC_PROT_ALL));
    OK(uc_reg_write(uc, UC_X86_REG_AX, &r_ax));
    OK(uc_reg_write(uc, UC_X86_REG_BX, &r_bx));
    OK(uc_reg_write(uc, UC_X86_REG_SI, &r_si));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_mem_read(uc, r_bx + r_si, &result, 1));
    TEST_CHECK(result == 7);
    OK(uc_close(uc));
}

static void test_x86_reg_save(void)
{
    uc_engine *uc;
    uc_context *ctx;
    char code[] = "\x40"; // inc eax
    int r_eax = 1;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_X86_REG_EAX, &r_eax));

    OK(uc_context_alloc(uc, &ctx));
    OK(uc_context_save(uc, ctx));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_EAX, &r_eax));
    TEST_CHECK(r_eax == 2);

    OK(uc_context_restore(uc, ctx));

    OK(uc_reg_read(uc, UC_X86_REG_EAX, &r_eax));
    TEST_CHECK(r_eax == 1);

    OK(uc_context_free(ctx));
    OK(uc_close(uc));
}

static bool
test_x86_invalid_mem_read_stop_in_cb_callback(uc_engine *uc, uc_mem_type type,
                                              uint64_t address, int size,
                                              uint64_t value, void *user_data)
{
    // False indicates that we fail to handle this ERROR and let the emulation
    // stop.
    //
    // Note that the memory must be mapped properly if we return true! Check
    // test_x86_mem_hook_all for example.
    return false;
}

static void test_x86_invalid_mem_read_stop_in_cb(void)
{
    uc_engine *uc;
    uc_hook hook;
    char code[] = "\x40\x8b\x1d\x00\x00\x10\x00\x42"; // inc eax; mov ebx,
                                                      // [0x100000]; inc edx
    int r_eax = 0x1234;
    int r_edx = 0x5678;
    int r_eip = 0;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_READ,
                   test_x86_invalid_mem_read_stop_in_cb_callback, NULL, 1, 0));
    OK(uc_reg_write(uc, UC_X86_REG_EAX, &r_eax));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &r_edx));

    uc_assert_err(
        UC_ERR_READ_UNMAPPED,
        uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    // The state of Unicorn should be correct at this time.
    OK(uc_reg_read(uc, UC_X86_REG_EIP, &r_eip));
    OK(uc_reg_read(uc, UC_X86_REG_EAX, &r_eax));
    OK(uc_reg_read(uc, UC_X86_REG_EDX, &r_edx));

    TEST_CHECK(r_eip == code_start + 1);
    TEST_CHECK(r_eax == 0x1235);
    TEST_CHECK(r_edx == 0x5678);

    OK(uc_close(uc));
}

static void test_x86_x87_fnstenv_callback(uc_engine *uc, uint64_t address,
                                          uint32_t size, void *user_data)
{
    uint32_t r_eip;
    uint32_t r_eax;
    uint32_t fnstenv[7];

    if (address == code_start + 4) { // The first fnstenv executed
        // Save the address of the fld.
        OK(uc_reg_read(uc, UC_X86_REG_EIP, &r_eip));
        *((uint32_t *)user_data) = r_eip;

        OK(uc_reg_read(uc, UC_X86_REG_EAX, &r_eax));
        OK(uc_mem_read(uc, r_eax, fnstenv, sizeof(fnstenv)));
        // Don't update FCS:FIP for fnop.
        TEST_CHECK(fnstenv[3] == 0);
    }
}

static void test_x86_x87_fnstenv(void)
{
    uc_engine *uc;
    uc_hook hook;
    char code[] =
        "\xd9\xd0\xd9\x30\xd9\x00\xd9\x30"; // fnop;fnstenv [eax];fld dword ptr
                                            // [eax];fnstenv [eax]
    uint32_t base = code_start + 3 * code_len;
    uint32_t last_eip;
    uint32_t fnstenv[7];

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_mem_map(uc, base, code_len, UC_PROT_ALL));
    OK(uc_reg_write(uc, UC_X86_REG_EAX, &base));

    OK(uc_hook_add(uc, &hook, UC_HOOK_CODE, test_x86_x87_fnstenv_callback,
                   &last_eip, 1, 0));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_mem_read(uc, base, fnstenv, sizeof(fnstenv)));
    // But update FCS:FIP for fld.
    TEST_CHECK(LEINT32(fnstenv[3]) == last_eip);

    OK(uc_close(uc));
}

static uint64_t test_x86_mmio_read_callback(uc_engine *uc, uint64_t offset,
                                            unsigned size, void *user_data)
{
    TEST_CHECK(offset == 4);
    TEST_CHECK(size == 4);

    return 0x19260817;
}

static void test_x86_mmio_write_callback(uc_engine *uc, uint64_t offset,
                                         unsigned size, uint64_t value,
                                         void *user_data)
{
    TEST_CHECK(offset == 4);
    TEST_CHECK(size == 4);
    TEST_CHECK(value == 0xdeadbeef);

    return;
}

static void test_x86_mmio(void)
{
    uc_engine *uc;
    int r_ecx = 0xdeadbeef;
    char code[] =
        "\x89\x0d\x04\x00\x02\x00\x8b\x0d\x04\x00\x02\x00"; // mov [0x20004],
                                                            // ecx; mov ecx,
                                                            // [0x20004]

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_mmio_map(uc, 0x20000, 0x1000, test_x86_mmio_read_callback, NULL,
                   test_x86_mmio_write_callback, NULL));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx));

    TEST_CHECK(r_ecx == 0x19260817);

    OK(uc_close(uc));
}

static bool test_x86_missing_code_callback(uc_engine *uc, uc_mem_type type,
                                           uint64_t address, int size,
                                           uint64_t value, void *user_data)
{
    char code[] = "\x41\x4a"; // inc ecx; dec edx;
    uint64_t algined_address = address & 0xFFFFFFFFFFFFF000ULL;
    int aligned_size = ((int)(size / 0x1000) + 1) * 0x1000;

    OK(uc_mem_map(uc, algined_address, aligned_size, UC_PROT_ALL));

    OK(uc_mem_write(uc, algined_address, code, sizeof(code) - 1));

    return true;
}

static void test_x86_missing_code(void)
{
    uc_engine *uc;
    uc_hook hook;
    int r_ecx = 0x1234;
    int r_edx = 0x7890;

    // Don't write any code by design.
    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &r_edx));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_UNMAPPED,
                   test_x86_missing_code_callback, NULL, 1, 0));

    OK(uc_emu_start(uc, code_start, code_start + 2, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_read(uc, UC_X86_REG_EDX, &r_edx));

    TEST_CHECK(r_ecx == 0x1235);
    TEST_CHECK(r_edx == 0x788f);

    OK(uc_close(uc));
}

static void test_x86_smc_xor(void)
{
    uc_engine *uc;
    /*
     * 0x1000 xor dword ptr [edi+0x3], eax ; edi=0x1000, eax=0xbc4177e6
     * 0x1003 dw 0x3ea98b13
     */
    char code[] = "\x31\x47\x03\x13\x8b\xa9\x3e";
    int r_edi = code_start;
    int r_eax = 0xbc4177e6;
    uint32_t result;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    uc_reg_write(uc, UC_X86_REG_EDI, &r_edi);
    uc_reg_write(uc, UC_X86_REG_EAX, &r_eax);

    OK(uc_emu_start(uc, code_start, code_start + 3, 0, 0));

    OK(uc_mem_read(uc, code_start + 3, (void *)&result, 4));

    TEST_CHECK(LEINT32(result) == (0x3ea98b13 ^ 0xbc4177e6));

    OK(uc_close(uc));
}

static void test_x86_smc_add(void)
{
    uc_engine *uc;
    uint64_t stack_base = 0x20000;
    uint64_t r_rsp;
    /*
     * mov qword ptr [rip+0x10], rax
     * mov word ptr [rip], 0x0548
     * [orig] mov eax, dword ptr [rax + 0x12345678]; [after SMC] 480578563412
     * add rax, 0x12345678 hlt
     */
    char code[] = "\x48\x89\x05\x10\x00\x00\x00\x66\xc7\x05\x00\x00\x00\x00\x48"
                  "\x05\x8b\x80\x78\x56\x34\x12\xf4";
    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof(code) - 1);

    OK(uc_mem_map(uc, stack_base, 0x2000, UC_PROT_ALL));
    r_rsp = stack_base + 0x1800;
    OK(uc_reg_write(uc, UC_X86_REG_RSP, &r_rsp));
    OK(uc_emu_start(uc, code_start, -1, 0, 0));

    OK(uc_close(uc));
}

static void test_x86_smc_mem_hook_callback(uc_engine *uc, uc_mem_type t,
                                           uint64_t addr, int size,
                                           uint64_t value, void *user_data)
{
    uint64_t write_addresses[] = {0x1030, 0x1010, 0x1010, 0x1018,
                                  0x1018, 0x1029, 0x1029};
    unsigned int *i = user_data;

    TEST_CHECK(*i < (sizeof(write_addresses) / sizeof(write_addresses[0])));
    TEST_CHECK(write_addresses[*i] == addr);
    (*i)++;
}

static void test_x86_smc_mem_hook(void)
{
    uc_engine *uc;
    uc_hook hook;
    uint64_t stack_base = 0x20000;
    uint64_t r_rsp;
    unsigned int i = 0;
    /*
     * mov qword ptr [rip+0x29], rax
     * mov word ptr [rip], 0x0548
     * [orig] mov eax, dword ptr [rax + 0x12345678]; [after SMC] 480578563412
     * add rax, 0x12345678 nop nop nop mov qword ptr [rip-0x08], rax mov word
     * ptr [rip], 0x0548 [orig] mov eax, dword ptr [rax + 0x12345678]; [after
     * SMC] 480578563412 add rax, 0x12345678 hlt
     */
    char code[] =
        "\x48\x89\x05\x29\x00\x00\x00\x66\xC7\x05\x00\x00\x00\x00\x48\x05\x8B"
        "\x80\x78\x56\x34\x12\x90\x90\x90\x48\x89\x05\xF8\xFF\xFF\xFF\x66\xC7"
        "\x05\x00\x00\x00\x00\x48\x05\x8B\x80\x78\x56\x34\x12\xF4";
    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof(code) - 1);

    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_WRITE, test_x86_smc_mem_hook_callback,
                   &i, 1, 0));
    OK(uc_mem_map(uc, stack_base, 0x2000, UC_PROT_ALL));
    r_rsp = stack_base + 0x1800;
    OK(uc_reg_write(uc, UC_X86_REG_RSP, &r_rsp));
    OK(uc_emu_start(uc, code_start, -1, 0, 0));

    OK(uc_close(uc));
}

static uint64_t test_x86_mmio_uc_mem_rw_read_callback(uc_engine *uc,
                                                      uint64_t offset,
                                                      unsigned size,
                                                      void *user_data)
{
    TEST_CHECK(offset == 8);
    TEST_CHECK(size == 4);

    return 0x19260817;
}

static void test_x86_mmio_uc_mem_rw_write_callback(uc_engine *uc,
                                                   uint64_t offset,
                                                   unsigned size,
                                                   uint64_t value,
                                                   void *user_data)
{
    TEST_CHECK(offset == 4);
    TEST_CHECK(size == 4);
    TEST_CHECK(value == 0xdeadbeef);

    return;
}

static void test_x86_mmio_uc_mem_rw(void)
{
    uc_engine *uc;
    int data = LEINT32(0xdeadbeef);

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));

    OK(uc_mmio_map(uc, 0x20000, 0x1000, test_x86_mmio_uc_mem_rw_read_callback,
                   NULL, test_x86_mmio_uc_mem_rw_write_callback, NULL));

    OK(uc_mem_write(uc, 0x20004, (void *)&data, 4));
    OK(uc_mem_read(uc, 0x20008, (void *)&data, 4));

    TEST_CHECK(LEINT32(data) == 0x19260817);

    OK(uc_close(uc));
}

static void test_x86_sysenter_hook(uc_engine *uc, void *user)
{
    *(int *)user = 1;
}

static void test_x86_sysenter(void)
{
    uc_engine *uc;
    char code[] = "\x0F\x34"; // sysenter
    uc_hook h;
    int called = 0;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);

    OK(uc_hook_add(uc, &h, UC_HOOK_INSN, test_x86_sysenter_hook, &called, 1, 0,
                   UC_X86_INS_SYSENTER));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    TEST_CHECK(called == 1);

    OK(uc_close(uc));
}

static int test_x86_hook_cpuid_callback(uc_engine *uc, void *data)
{
    uint32_t reg = 7;
    uint32_t eip;

    OK(uc_reg_read(uc, UC_X86_REG_EIP, (void*)&eip));
    OK(uc_reg_write(uc, UC_X86_REG_EAX, &reg));

    TEST_CHECK(eip == code_start + 1);
    // Overwrite the cpuid instruction.
    return 1;
}

static void test_x86_hook_cpuid(void)
{
    uc_engine *uc;
    char code[] = "\x40\x0F\xA2"; // INC EAX; CPUID
    uc_hook h;
    int reg;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);

    OK(uc_hook_add(uc, &h, UC_HOOK_INSN, test_x86_hook_cpuid_callback, NULL, 1,
                   0, UC_X86_INS_CPUID));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_EAX, &reg));

    TEST_CHECK(reg == 7);

    OK(uc_close(uc));
}

static void test_x86_486_cpuid(void)
{
    uc_engine *uc;
    uint32_t eax;
    uint32_t ebx;

    char code[] = {0x31, 0xC0, 0x0F, 0xA2}; // XOR EAX EAX; CPUID

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_ctl_set_cpu_model(uc, UC_CPU_X86_486));
    OK(uc_mem_map(uc, 0, 4 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0, code, sizeof(code) / sizeof(code[0])));
    OK(uc_emu_start(uc, 0, sizeof(code) / sizeof(code[0]), 0, 0));

    /* Read eax after emulation */
    OK(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
    OK(uc_reg_read(uc, UC_X86_REG_EBX, &ebx));

    TEST_CHECK(eax != 0);
    TEST_CHECK(ebx == 0x756e6547); // magic string "Genu" for intel cpu

    OK(uc_close(uc));
}

// This is a regression bug.
static void test_x86_clear_tb_cache(void)
{
    uc_engine *uc;
    char code[] = "\x83\xc1\x01\x4a"; // ADD ecx, 1; DEC edx;
    int r_ecx = 0x1234;
    int r_edx = 0x7890;
    uint64_t code_start = 0x1240; // Choose this address by design
    uint64_t code_len = 0x1000;

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_mem_map(uc, code_start & (1 << 12), code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &r_edx));

    // This emulation should take no effect at all.
    OK(uc_emu_start(uc, code_start, code_start, 0, 0));

    // Emulate ADD ecx, 1.
    OK(uc_emu_start(uc, code_start, code_start + 3, 0, 0));

    // If tb cache is not cleared, edx would be still 0x7890
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_read(uc, UC_X86_REG_EDX, &r_edx));

    TEST_CHECK(r_ecx == 0x1236);
    TEST_CHECK(r_edx == 0x788f);

    OK(uc_close(uc));
}

static void test_x86_clear_count_cache(void)
{
    uc_engine *uc;
    // uc_emu_start will clear last TB when exiting so generating a tb at last
    // by design
    char code[] =
        "\x83\xc1\x01\x4a\xeb\x00\x83\xc3\x01"; // ADD ecx, 1; DEC edx;
                                                // jmp t;
                                                // t:
                                                // ADD ebx, 1
    int r_ecx = 0x1234;
    int r_edx = 0x7890;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &r_edx));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 2));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_read(uc, UC_X86_REG_EDX, &r_edx));

    TEST_CHECK(r_ecx == 0x1236);
    TEST_CHECK(r_edx == 0x788e);

    OK(uc_close(uc));
}

// This is a regression bug.
static void test_x86_clear_empty_tb(void)
{
    uc_engine *uc;
    // lb:
    //    add ecx, 1;
    //    cmp ecx, 0;
    //    jz lb;
    //    dec edx;
    char code[] = "\x83\xc1\x01\x83\xf9\x00\x74\xf8\x4a";
    int r_edx = 0x7890;
    uint64_t code_start = 0x1240; // Choose this address by design
    uint64_t code_len = 0x1000;

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_mem_map(uc, code_start & (1 << 12), code_len, UC_PROT_ALL));
    OK(uc_mem_write(uc, code_start, code, sizeof(code)));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &r_edx));

    // Make sure we generate an empty tb at the exit address by stopping at dec
    // edx.
    OK(uc_emu_start(uc, code_start, code_start + 8, 0, 0));

    // If tb cache is not cleared, edx would be still 0x7890
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_EDX, &r_edx));

    TEST_CHECK(r_edx == 0x788f);

    OK(uc_close(uc));
}

typedef struct _HOOK_TCG_OP_RESULT {
    uint64_t address;
    uint64_t arg1;
    uint64_t arg2;
} HOOK_TCG_OP_RESULT;

typedef struct _HOOK_TCG_OP_RESULTS {
    HOOK_TCG_OP_RESULT results[128];
    uint64_t len;
} HOOK_TCG_OP_RESULTS;

static void test_x86_hook_tcg_op_cb(uc_engine *uc, uint64_t address,
                                    uint64_t arg1, uint64_t arg2, uint32_t size,
                                    void *data)
{
    HOOK_TCG_OP_RESULTS *results = (HOOK_TCG_OP_RESULTS *)data;
    HOOK_TCG_OP_RESULT *result = &results->results[results->len++];

    result->address = address;
    result->arg1 = arg1;
    result->arg2 = arg2;
}

static void test_x86_hook_tcg_op(void)
{
    uc_engine *uc;
    uc_hook h;
    int flag;
    HOOK_TCG_OP_RESULTS results;
    // sub esi, [0x1000];
    // sub eax, ebx;
    // sub eax, 1;
    // cmp eax, 0;
    // cmp ebx, edx;
    // cmp esi, [0x1000];
    char code[] = "\x2b\x35\x00\x10\x00\x00\x29\xd8\x83\xe8\x01\x83\xf8\x00\x39"
                  "\xd3\x3b\x35\x00\x10\x00\x00";
    int r_eax = 0x1234;
    int r_ebx = 2;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_X86_REG_EAX, &r_eax));
    OK(uc_reg_write(uc, UC_X86_REG_EBX, &r_ebx));

    memset(&results, 0, sizeof(HOOK_TCG_OP_RESULTS));
    flag = 0;
    OK(uc_hook_add(uc, &h, UC_HOOK_TCG_OPCODE, test_x86_hook_tcg_op_cb,
                   &results, 0, -1, UC_TCG_OP_SUB, flag));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_hook_del(uc, h));

    TEST_CHECK(results.len == 6);

    memset(&results, 0, sizeof(HOOK_TCG_OP_RESULTS));
    flag = UC_TCG_OP_FLAG_DIRECT;
    OK(uc_hook_add(uc, &h, UC_HOOK_TCG_OPCODE, test_x86_hook_tcg_op_cb,
                   &results, 0, -1, UC_TCG_OP_SUB, flag));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_hook_del(uc, h));

    TEST_CHECK(results.len == 3);

    memset(&results, 0, sizeof(HOOK_TCG_OP_RESULTS));
    flag = UC_TCG_OP_FLAG_CMP;
    OK(uc_hook_add(uc, &h, UC_HOOK_TCG_OPCODE, test_x86_hook_tcg_op_cb,
                   &results, 0, -1, UC_TCG_OP_SUB, flag));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));
    OK(uc_hook_del(uc, h));

    TEST_CHECK(results.len == 3);

    OK(uc_close(uc));
}

static bool test_x86_cmpxchg_mem_hook(uc_engine *uc, uc_mem_type type,
                                      uint64_t address, int size, int64_t val,
                                      void *data)
{
    if (type == UC_MEM_READ) {
        *((int *)data) |= 1;
    } else {
        *((int *)data) |= 2;
    }

    return true;
}

static void test_x86_cmpxchg(void)
{
    uc_engine *uc;
    char code[] = "\x0F\xC7\x0D\xE0\xBE\xAD\xDE"; // cmpxchg8b [0xdeadbee0]
    int r_zero = 0;
    int r_aaaa = 0x41414141;
    uint64_t mem;
    uc_hook h;
    int result = 0;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_mem_map(uc, 0xdeadb000, 0x1000, UC_PROT_ALL));
    OK(uc_hook_add(uc, &h, UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                   test_x86_cmpxchg_mem_hook, &result, 1, 0));

    OK(uc_reg_write(uc, UC_X86_REG_EDX, &r_zero));
    OK(uc_reg_write(uc, UC_X86_REG_EAX, &r_zero));
    OK(uc_reg_write(uc, UC_X86_REG_ECX, &r_aaaa));
    OK(uc_reg_write(uc, UC_X86_REG_EBX, &r_aaaa));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_mem_read(uc, 0xdeadbee0, &mem, 8));

    TEST_CHECK(mem == 0x4141414141414141);

    // Both read and write happened.
    TEST_CHECK(result == 3);

    OK(uc_close(uc));
}

static void test_x86_nested_emu_start_cb(uc_engine *uc, uint64_t addr,
                                         size_t size, void *data)
{
    OK(uc_emu_start(uc, code_start + 1, code_start + 2, 0, 0));
}

static void test_x86_nested_emu_start(void)
{
    uc_engine *uc;
    char code[] = "\x41\x4a"; // INC ecx; DEC edx;
    int r_ecx = 0x1234;
    int r_edx = 0x7890;
    uc_hook h;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &r_edx));
    // Emulate DEC in the nested hook.
    OK(uc_hook_add(uc, &h, UC_HOOK_CODE, test_x86_nested_emu_start_cb, NULL,
                   code_start, code_start));

    // Emulate INC
    OK(uc_emu_start(uc, code_start, code_start + 1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_read(uc, UC_X86_REG_EDX, &r_edx));

    TEST_CHECK(r_ecx == 0x1235);
    TEST_CHECK(r_edx == 0x788f);

    OK(uc_close(uc));
}

static void test_x86_nested_emu_stop_cb(uc_engine *uc, uint64_t addr,
                                        size_t size, void *data)
{
    OK(uc_emu_start(uc, code_start + 1, code_start + 2, 0, 0));
    // ecx shouldn't be changed!
    OK(uc_emu_stop(uc));
}

static void test_x86_nested_emu_stop(void)
{
    uc_engine *uc;
    // INC ecx; DEC edx; DEC edx;
    char code[] = "\x41\x4a\x4a";
    int r_ecx = 0x1234;
    int r_edx = 0x7890;
    uc_hook h;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_write(uc, UC_X86_REG_EDX, &r_edx));
    // Emulate DEC in the nested hook.
    OK(uc_hook_add(uc, &h, UC_HOOK_CODE, test_x86_nested_emu_stop_cb, NULL,
                   code_start, code_start));

    OK(uc_emu_start(uc, code_start, code_start + 3, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx));
    OK(uc_reg_read(uc, UC_X86_REG_EDX, &r_edx));

    TEST_CHECK(r_ecx == 0x1234);
    TEST_CHECK(r_edx == 0x788f);

    OK(uc_close(uc));
}

static void test_x86_nested_emu_start_error_cb(uc_engine *uc, uint64_t addr,
                                               size_t size, void *data)
{
    uc_assert_err(UC_ERR_READ_UNMAPPED,
                  uc_emu_start(uc, code_start + 2, 0, 0, 0));
}

static void test_x86_64_nested_emu_start_error(void)
{
    uc_engine *uc;
    // "nop;nop;mov rax, [0x10000]"
    char code[] = "\x90\x90\x48\xa1\x00\x00\x01\x00\x00\x00\x00\x00";
    uc_hook hk;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof(code) - 1);
    OK(uc_hook_add(uc, &hk, UC_HOOK_CODE, test_x86_nested_emu_start_error_cb,
                   NULL, code_start, code_start));

    // This call shouldn't fail!
    OK(uc_emu_start(uc, code_start, code_start + 2, 0, 0));

    OK(uc_close(uc));
}

static void test_x86_eflags_reserved_bit(void)
{
    uc_engine *uc;
    uint32_t r_eflags;

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));

    OK(uc_reg_read(uc, UC_X86_REG_EFLAGS, &r_eflags));

    TEST_CHECK((r_eflags & 2) != 0);

    OK(uc_reg_write(uc, UC_X86_REG_EFLAGS, &r_eflags));

    OK(uc_reg_read(uc, UC_X86_REG_EFLAGS, &r_eflags));

    TEST_CHECK((r_eflags & 2) != 0);

    OK(uc_close(uc));
}

static void test_x86_nested_uc_emu_start_exits_cb(uc_engine *uc, uint64_t addr,
                                                  size_t size, void *data)
{
    OK(uc_emu_start(uc, code_start + 5, code_start + 6, 0, 0));
}

static void test_x86_nested_uc_emu_start_exits(void)
{
    uc_engine *uc;
    //  cmp eax, 0
    //  jnz t
    //  nop <-- nested emu_start
    // t:mov dword ptr [eax], 0
    char code[] = "\x83\xf8\x00\x75\x01\x90\xc7\x00\x00\x00\x00\x00";
    uc_hook hk;
    uint32_t r_pc;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);

    OK(uc_hook_add(uc, &hk, UC_HOOK_CODE, test_x86_nested_uc_emu_start_exits_cb,
                   NULL, code_start, code_start));
    OK(uc_emu_start(uc, code_start, code_start + 5, 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_EIP, &r_pc));

    TEST_CHECK(r_pc == code_start + 5);

    OK(uc_close(uc));
}

static bool test_x86_correct_address_in_small_jump_hook_callback(
    uc_engine *uc, int type, uint64_t address, int size, int64_t value,
    void *user_data)
{
    // Check registers
    uint64_t r_rax = 0x0;
    uint64_t r_rip = 0x0;
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &r_rax));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &r_rip));
    TEST_CHECK(r_rax == 0x7F00);
    TEST_CHECK(r_rip == 0x7F00);

    // Check address
    // printf("%lx\n", address);
    TEST_CHECK(address == 0x7F00);

    return false;
}

static void test_x86_correct_address_in_small_jump_hook(void)
{
    uc_engine *uc;
    // movabs $0x7F00, %rax
    // jmp  *%rax
    char code[] = "\x48\xb8\x00\x7F\x00\x00\x00\x00\x00\x00\xff\xe0";

    uint64_t r_rax = 0x0;
    uint64_t r_rip = 0x0;
    uc_hook hook;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof(code) - 1);
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_UNMAPPED,
                   test_x86_correct_address_in_small_jump_hook_callback, NULL,
                   1, 0));

    uc_assert_err(
        UC_ERR_FETCH_UNMAPPED,
        uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_RAX, &r_rax));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &r_rip));
    TEST_CHECK(r_rax == 0x7F00);
    TEST_CHECK(r_rip == 0x7F00);

    OK(uc_close(uc));
}

static bool test_x86_correct_address_in_long_jump_hook_callback(
    uc_engine *uc, int type, uint64_t address, int size, int64_t value,
    void *user_data)
{
    // Check registers
    uint64_t r_rax = 0x0;
    uint64_t r_rip = 0x0;
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &r_rax));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &r_rip));
    TEST_CHECK(r_rax == 0x7FFFFFFFFFFFFF00);
    TEST_CHECK(r_rip == 0x7FFFFFFFFFFFFF00);

    // Check address
    // printf("%lx\n", address);
    TEST_CHECK(address == 0x7FFFFFFFFFFFFF00);

    return false;
}

static void test_x86_correct_address_in_long_jump_hook(void)
{
    uc_engine *uc;
    // movabs $0x7FFFFFFFFFFFFF00, %rax
    // jmp  *%rax
    char code[] = "\x48\xb8\x00\xff\xff\xff\xff\xff\xff\x7f\xff\xe0";

    uint64_t r_rax = 0x0;
    uint64_t r_rip = 0x0;
    uc_hook hook;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof(code) - 1);
    OK(uc_ctl_tlb_mode(uc, UC_TLB_VIRTUAL));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_UNMAPPED,
                   test_x86_correct_address_in_long_jump_hook_callback, NULL, 1,
                   0));

    uc_assert_err(
        UC_ERR_FETCH_UNMAPPED,
        uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_RAX, &r_rax));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &r_rip));
    TEST_CHECK(r_rax == 0x7FFFFFFFFFFFFF00);
    TEST_CHECK(r_rip == 0x7FFFFFFFFFFFFF00);

    OK(uc_close(uc));
}

static void test_x86_avx_vaddps_ymm(void)
{
    uc_engine *uc;
    uint64_t ymm0[4], ymm1[4], ymm2[4];

    /*
     * Use register writes to set up YMM values directly, then vaddps.
     *
     * vaddps  ymm2, ymm0, ymm1; C5 FC 58 D1
     */
    char code[] = {
        '\xC5', '\xFC', '\x58', '\xD1',             /* vaddps ymm2, ymm0, ymm1 */
    };

    /* Float data: 8 floats per YMM register */
    float src0[8] = { 1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f };
    float src1[8] = { 10.0f, 20.0f, 30.0f, 40.0f, 50.0f, 60.0f, 70.0f, 80.0f };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));

    /* Write code */
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* Set YMM registers directly */
    OK(uc_reg_write(uc, UC_X86_REG_YMM0, src0));
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, src1));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    /* Read ymm2 result */
    OK(uc_reg_read(uc, UC_X86_REG_YMM2, &ymm2));

    /* Verify vaddps result: ymm2 = ymm0 + ymm1 */
    float *result = (float *)ymm2;
    TEST_CHECK(result[0] == 11.0f);  /* 1 + 10 */
    TEST_CHECK(result[1] == 22.0f);  /* 2 + 20 */
    TEST_CHECK(result[2] == 33.0f);  /* 3 + 30 */
    TEST_CHECK(result[3] == 44.0f);  /* 4 + 40 */
    TEST_CHECK(result[4] == 55.0f);  /* 5 + 50 */
    TEST_CHECK(result[5] == 66.0f);  /* 6 + 60 */
    TEST_CHECK(result[6] == 77.0f);  /* 7 + 70 */
    TEST_CHECK(result[7] == 88.0f);  /* 8 + 80 */

    OK(uc_close(uc));
}

static void test_x86_avx_vmovdqu_ymm(void)
{
    uc_engine *uc;
    uint64_t ymm0[4];

    /*
     * vmovdqu ymm0, [rax]     ; C5 FE 6F 00
     */
    char code[] = { '\xC5', '\xFE', '\x6F', '\x00' };

    uint64_t data[4] = { 0x1111111122222222ULL, 0x3333333344444444ULL,
                          0x5555555566666666ULL, 0x7777777788888888ULL };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));
    OK(uc_mem_write(uc, 0x2000, data, sizeof(data)));

    uint64_t rax = 0x2000;
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_YMM0, &ymm0));
    TEST_CHECK(ymm0[0] == 0x1111111122222222ULL);
    TEST_CHECK(ymm0[1] == 0x3333333344444444ULL);
    TEST_CHECK(ymm0[2] == 0x5555555566666666ULL);
    TEST_CHECK(ymm0[3] == 0x7777777788888888ULL);

    OK(uc_close(uc));
}

static void test_x86_avx_vzeroupper(void)
{
    uc_engine *uc;
    uint64_t ymm0[4];

    /*
     * Set ymm0 to all-ones via register write, then execute vzeroupper.
     * vzeroupper should zero the upper 128 bits of all YMM registers.
     *
     * vzeroupper  ; C5 F8 77
     */
    char code[] = { '\xC5', '\xF8', '\x77' };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* Set ymm0 to all-ones */
    uint64_t all_ones[4] = { 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
                              0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL };
    OK(uc_reg_write(uc, UC_X86_REG_YMM0, &all_ones));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_YMM0, &ymm0));
    /* Lower 128 bits should be preserved */
    TEST_CHECK(ymm0[0] == 0xFFFFFFFFFFFFFFFFULL);
    TEST_CHECK(ymm0[1] == 0xFFFFFFFFFFFFFFFFULL);
    /* Upper 128 bits should be zeroed */
    TEST_CHECK(ymm0[2] == 0);
    TEST_CHECK(ymm0[3] == 0);

    OK(uc_close(uc));
}

static void test_x86_avx_vmovdqu_store(void)
{
    uc_engine *uc;
    uint64_t data_out[4] = {0};

    /*
     * Set ymm0 via register write, then store to memory.
     *
     * vmovdqu [rax], ymm0  ; C5 FE 7F 00
     */
    char code[] = { '\xC5', '\xFE', '\x7F', '\x00' };

    uint64_t ymm_val[4] = { 0xAAAABBBBCCCCDDDDULL, 0x1111222233334444ULL,
                             0x5555666677778888ULL, 0x9999AAAABBBBCCCCULL };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    uint64_t rax = 0x2000;
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    OK(uc_reg_write(uc, UC_X86_REG_YMM0, ymm_val));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    OK(uc_mem_read(uc, 0x2000, data_out, sizeof(data_out)));
    TEST_CHECK(data_out[0] == 0xAAAABBBBCCCCDDDDULL);
    TEST_CHECK(data_out[1] == 0x1111222233334444ULL);
    TEST_CHECK(data_out[2] == 0x5555666677778888ULL);
    TEST_CHECK(data_out[3] == 0x9999AAAABBBBCCCCULL);

    OK(uc_close(uc));
}

static void test_x86_avx_vbroadcastss(void)
{
    uc_engine *uc;
    uint64_t ymm1[4] = {0};
    /*
     * Store 0x42280000 (42.0f) at [rax], then broadcast to all 8 dwords of ymm1.
     *
     * vbroadcastss ymm1, [rax]  ; C4 E2 7D 18 08
     */
    char code[] = { '\xC4', '\xE2', '\x7D', '\x18', '\x08' };

    uint32_t float_val = 0x42280000; /* 42.0f */

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));
    OK(uc_mem_write(uc, 0x2000, &float_val, sizeof(float_val)));

    uint64_t rax = 0x2000;
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_YMM1, ymm1));
    /* All 8 dwords should be 0x42280000 */
    TEST_CHECK(ymm1[0] == 0x4228000042280000ULL);
    TEST_CHECK(ymm1[1] == 0x4228000042280000ULL);
    TEST_CHECK(ymm1[2] == 0x4228000042280000ULL);
    TEST_CHECK(ymm1[3] == 0x4228000042280000ULL);

    OK(uc_close(uc));
}

static void test_x86_avx_vperm2f128(void)
{
    uc_engine *uc;
    uint64_t ymm0[4] = {0};

    /*
     * vperm2f128 ymm0, ymm1, ymm2, 0x31
     *   imm8=0x31: low lane = lane 1 of ymm1 (src1[1]), high lane = lane 1 of ymm2 (src2[1])
     *
     * C4 E3 75 06 C2 31
     *   VEX.256, pp=01(66), mmmmm=00011(0F3A), W=0
     *   vvvv=~1=0b1110 -> ymm1
     *   opcode=06, modrm=C2 (mod=3, reg=0, rm=2)
     *   imm8=0x31
     */
    char code[] = {
        '\xC4', '\xE3', '\x75', '\x06', '\xC2', '\x31'
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* ymm1 = { lane0: 0x1111111122222222 0x3333333344444444,
     *           lane1: 0xAAAAAAAABBBBBBBB 0xCCCCCCCCDDDDDDDD } */
    uint64_t ymm1[4] = { 0x1111111122222222ULL, 0x3333333344444444ULL,
                          0xAAAAAAAABBBBBBBBULL, 0xCCCCCCCCDDDDDDDDULL };
    /* ymm2 = { lane0: 0x5555555566666666 0x7777777788888888,
     *           lane1: 0xEEEEEEEEFFFFFFFF 0x9999999900000000 } */
    uint64_t ymm2[4] = { 0x5555555566666666ULL, 0x7777777788888888ULL,
                          0xEEEEEEEEFFFFFFFFULL, 0x9999999900000000ULL };
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ymm1));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, ymm2));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ymm0));
    /* imm8=0x31: low 4 bits=0x1 -> src1 lane 1, high 4 bits=0x3 -> src2 lane 1 */
    TEST_CHECK(ymm0[0] == 0xAAAAAAAABBBBBBBBULL);  /* ymm1 lane 1 */
    TEST_CHECK(ymm0[1] == 0xCCCCCCCCDDDDDDDDULL);
    TEST_CHECK(ymm0[2] == 0xEEEEEEEEFFFFFFFFULL);  /* ymm2 lane 1 */
    TEST_CHECK(ymm0[3] == 0x9999999900000000ULL);

    OK(uc_close(uc));
}

static void test_x86_avx_vinsertf128(void)
{
    uc_engine *uc;
    uint64_t ymm0[4] = {0};

    /*
     * vinsertf128 ymm0, ymm1, xmm2, 1
     *   Insert xmm2 into high 128 bits of ymm1, store in ymm0.
     *
     * C4 E3 75 18 C2 01
     *   VEX.256, pp=01(66), mmmmm=00011(0F3A), W=0
     *   vvvv=~1=0b1110 -> ymm1
     *   opcode=18, modrm=C2 (mod=3, reg=0, rm=2)
     *   imm8=01
     */
    char code[] = {
        '\xC4', '\xE3', '\x75', '\x18', '\xC2', '\x01'
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* ymm1 = { 0x1111111111111111 0x2222222222222222
     *           0x3333333333333333 0x4444444444444444 } */
    uint64_t ymm1[4] = { 0x1111111111111111ULL, 0x2222222222222222ULL,
                          0x3333333333333333ULL, 0x4444444444444444ULL };
    /* xmm2 = { 0xAAAAAAAAAAAAAAAA 0xBBBBBBBBBBBBBBBB } */
    uint64_t ymm2[4] = { 0xAAAAAAAAAAAAAAAAULL, 0xBBBBBBBBBBBBBBBBULL,
                          0, 0 };
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ymm1));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, ymm2));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ymm0));
    /* Low lane from ymm1, high lane replaced by xmm2 */
    TEST_CHECK(ymm0[0] == 0x1111111111111111ULL);
    TEST_CHECK(ymm0[1] == 0x2222222222222222ULL);
    TEST_CHECK(ymm0[2] == 0xAAAAAAAAAAAAAAAAULL);
    TEST_CHECK(ymm0[3] == 0xBBBBBBBBBBBBBBBBULL);

    OK(uc_close(uc));
}

static void test_x86_avx_vextractf128(void)
{
    uc_engine *uc;
    uint64_t xmm0[2] = {0};

    /*
     * vextractf128 xmm0, ymm1, 1
     *   Extract high 128 bits of ymm1 into xmm0.
     *
     * C4 E3 7D 19 C8 01
     *   VEX.256, pp=01(66), mmmmm=00011(0F3A), W=0
     *   vvvv=0b1111 (unused for vextractf128)
     *   opcode=19, modrm=C8 (mod=3, reg=1, rm=0)
     *   imm8=01
     */
    char code[] = {
        '\xC4', '\xE3', '\x7D', '\x19', '\xC8', '\x01'
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* ymm1 = { 0x1111111111111111 0x2222222222222222
     *           0xAAAAAAAAAAAAAAAA 0xBBBBBBBBBBBBBBBB } */
    uint64_t ymm1[4] = { 0x1111111111111111ULL, 0x2222222222222222ULL,
                          0xAAAAAAAAAAAAAAAAULL, 0xBBBBBBBBBBBBBBBBULL };
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ymm1));

    /* Set xmm0 to garbage to confirm it gets overwritten */
    uint64_t garbage[4] = { 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
                             0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL };
    OK(uc_reg_write(uc, UC_X86_REG_YMM0, garbage));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    /* Read full ymm0 to check upper bits are zeroed */
    uint64_t ymm0_full[4] = {0};
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ymm0_full));
    /* xmm0 should have ymm1's high lane */
    TEST_CHECK(ymm0_full[0] == 0xAAAAAAAAAAAAAAAAULL);
    TEST_CHECK(ymm0_full[1] == 0xBBBBBBBBBBBBBBBBULL);
    /* Upper 128 bits should be zeroed by the helper */
    TEST_CHECK(ymm0_full[2] == 0);
    TEST_CHECK(ymm0_full[3] == 0);

    OK(uc_close(uc));
}

static void test_x86_avx_vpermilps(void)
{
    uc_engine *uc;
    uint64_t ymm0[4] = {0};

    /*
     * vpermilps ymm0, ymm1, 0x1B  (reverse dword order within each lane)
     * imm8=0x1B = 0b00_01_10_11 -> select [3,2,1,0] within each lane
     *
     * C4 E3 7D 04 C1 1B
     *   VEX.256, pp=01(66), mmmmm=00011(0F3A), W=0
     *   vvvv=0b1111 (unused)
     *   opcode=04, modrm=C1 (mod=3, reg=0, rm=1)
     *   imm8=0x1B
     */
    char code[] = {
        '\xC4', '\xE3', '\x7D', '\x04', '\xC1', '\x1B'
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* ymm1 = { dwords: 0x11111111 0x22222222 0x33333333 0x44444444
     *                   0x55555555 0x66666666 0x77777777 0x88888888 } */
    uint64_t ymm1[4] = { 0x2222222211111111ULL, 0x4444444433333333ULL,
                          0x6666666655555555ULL, 0x8888888877777777ULL };
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ymm1));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ymm0));
    /* imm=0x1B reverses: dword0=src[3], dword1=src[2], dword2=src[1], dword3=src[0]
     * Lane 0: 0x44444444 0x33333333 0x22222222 0x11111111
     * Lane 1: 0x88888888 0x77777777 0x66666666 0x55555555 */
    TEST_CHECK(ymm0[0] == 0x3333333344444444ULL);
    TEST_CHECK(ymm0[1] == 0x1111111122222222ULL);
    TEST_CHECK(ymm0[2] == 0x7777777788888888ULL);
    TEST_CHECK(ymm0[3] == 0x5555555566666666ULL);

    OK(uc_close(uc));
}

static void test_x86_avx_vpermilpd(void)
{
    uc_engine *uc;
    uint64_t ymm0[4] = {0};

    /*
     * vpermilpd ymm0, ymm1, 0x05
     * imm8=0x05 = 0b0101 -> bit0=1, bit1=0, bit2=1, bit3=0
     * For YMM: qword0=src_lane0[1], qword1=src_lane0[0],
     *          qword2=src_lane1[1], qword3=src_lane1[0]
     *
     * C4 E3 7D 05 C1 05
     *   VEX.256, pp=01(66), mmmmm=00011(0F3A), W=0
     *   vvvv=0b1111 (unused)
     *   opcode=05, modrm=C1 (mod=3, reg=0, rm=1)
     *   imm8=0x05
     */
    char code[] = {
        '\xC4', '\xE3', '\x7D', '\x05', '\xC1', '\x05'
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* ymm1 = { 0xAAAAAAAAAAAAAAAA 0xBBBBBBBBBBBBBBBB
     *           0xCCCCCCCCCCCCCCCC 0xDDDDDDDDDDDDDDDD } */
    uint64_t ymm1[4] = { 0xAAAAAAAAAAAAAAAAULL, 0xBBBBBBBBBBBBBBBBULL,
                          0xCCCCCCCCCCCCCCCCULL, 0xDDDDDDDDDDDDDDDDULL };
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ymm1));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ymm0));
    /* bit0=1: qword0 = lane0[1] = 0xBBBBBBBBBBBBBBBB
     * bit1=0: qword1 = lane0[0] = 0xAAAAAAAAAAAAAAAA
     * bit2=1: qword2 = lane1[1] = 0xDDDDDDDDDDDDDDDD
     * bit3=0: qword3 = lane1[0] = 0xCCCCCCCCCCCCCCCC */
    TEST_CHECK(ymm0[0] == 0xBBBBBBBBBBBBBBBBULL);
    TEST_CHECK(ymm0[1] == 0xAAAAAAAAAAAAAAAAULL);
    TEST_CHECK(ymm0[2] == 0xDDDDDDDDDDDDDDDDULL);
    TEST_CHECK(ymm0[3] == 0xCCCCCCCCCCCCCCCCULL);

    OK(uc_close(uc));
}

static void test_x86_avx_vpminsd(void)
{
    uc_engine *uc;

    /*
     * vpminsd ymm0, ymm1, ymm2 - packed signed dword min (256-bit)
     *
     * C4 E2 75 39 C2
     *   VEX.256, pp=01(66), mmmmm=00010(0F38), W=0
     *   vvvv=~1=0b1110 -> ymm1
     *   opcode=39, modrm=C2 (mod=3, reg=0, rm=2)
     */
    char code[] = {
        '\xC4', '\xE2', '\x75', '\x39', '\xC2'
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* ymm1 = signed dwords: 5, -3, 10, -20, 100, -200, 0, 1 */
    uint64_t ymm1[4] = { 0xFFFFFFFD00000005ULL, 0xFFFFFFEC0000000AULL,
                          0xFFFFFF3800000064ULL, 0x0000000100000000ULL };
    /* ymm2 = signed dwords: 3, -1, 15, -10, 50, -100, 1, 0 */
    uint64_t ymm2[4] = { 0xFFFFFFFF00000003ULL, 0xFFFFFFF60000000FULL,
                          0xFFFFFF9C00000032ULL, 0x0000000000000001ULL };
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ymm1));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, ymm2));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    uint64_t ymm0[4] = {0};
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ymm0));
    /* min(5,3)=3, min(-3,-1)=-3, min(10,15)=10, min(-20,-10)=-20 */
    TEST_CHECK(ymm0[0] == 0xFFFFFFFD00000003ULL);
    TEST_CHECK(ymm0[1] == 0xFFFFFFEC0000000AULL);
    /* min(100,50)=50, min(-200,-100)=-200, min(0,1)=0, min(1,0)=0 */
    TEST_CHECK(ymm0[2] == 0xFFFFFF3800000032ULL);
    TEST_CHECK(ymm0[3] == 0x0000000000000000ULL);

    OK(uc_close(uc));
}

static void test_x86_avx_vtestps(void)
{
    uc_engine *uc;

    /*
     * vtestps ymm0, ymm1  - test packed single-precision sign bits
     *
     * C4 E2 7D 0E C1
     *   VEX.256, pp=01(66), mmmmm=00010(0F38), W=0
     *   opcode=0E, modrm=C1 (mod=3, reg=0, rm=1)
     *
     * Sets ZF if (ymm1 AND ymm0) sign bits are all zero
     * Sets CF if (ymm1 AND NOT ymm0) sign bits are all zero
     */
    char code[] = {
        '\xC4', '\xE2', '\x7D', '\x0E', '\xC1', /* vtestps ymm0, ymm1 */
        '\x9F',                                    /* lahf */
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* ymm0 = all sign bits set (negative floats) */
    uint64_t ymm0[4] = { 0x8000000080000000ULL, 0x8000000080000000ULL,
                          0x8000000080000000ULL, 0x8000000080000000ULL };
    /* ymm1 = all sign bits set */
    uint64_t ymm1[4] = { 0x8000000080000000ULL, 0x8000000080000000ULL,
                          0x8000000080000000ULL, 0x8000000080000000ULL };
    OK(uc_reg_write(uc, UC_X86_REG_YMM0, ymm0));
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ymm1));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    /* ymm1 AND ymm0 = all sign bits set -> ZF=0
     * ymm1 AND NOT ymm0 = 0 -> CF=1 */
    uint64_t rax = 0;
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
    uint8_t ah = (rax >> 8) & 0xFF;
    /* ZF should be 0 (bit 6 of ah), CF should be 0 (bit 0 of ah)
     * Wait - CF=1 means "all ANDN sign bits zero", so CF flag = 1 in EFLAGS
     * but lahf stores flags in ah: bit 0 = CF
     * VTESTPS: CF set if ANDN sign bits all zero. Here ANDN = ymm1 & ~ymm0.
     * ymm1 has bit31 set, ~ymm0 has bit31 clear => ANDN bit31 = 0.
     * All ANDN sign bits are 0, so CF=1. */
    TEST_CHECK((ah & 0x01) == 0x01); /* CF=1 */
    TEST_CHECK((ah & 0x40) == 0x00); /* ZF=0 */

    OK(uc_close(uc));
}

static void test_x86_avx_vtestpd(void)
{
    uc_engine *uc;

    /*
     * vtestpd xmm0, xmm1  - VEX.128 form
     *
     * C4 E2 79 0F C1
     *   VEX.128, pp=01(66), mmmmm=00010(0F38), W=0
     *   opcode=0F, modrm=C1 (mod=3, reg=0, rm=1)
     */
    char code[] = {
        '\xC4', '\xE2', '\x79', '\x0F', '\xC1', /* vtestpd xmm0, xmm1 */
        '\x9F',                                    /* lahf */
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* xmm0 = 0 (all zero) */
    uint64_t xmm0[2] = { 0, 0 };
    /* xmm1 = sign bits set */
    uint64_t xmm1[2] = { 0x8000000000000000ULL, 0x8000000000000000ULL };
    OK(uc_reg_write(uc, UC_X86_REG_XMM0, xmm0));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, xmm1));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    /* AND(xmm1, xmm0) = 0 -> all sign bits zero -> ZF=1
     * ANDN(xmm1, ~xmm0) -> xmm1 & ~xmm0 = has sign bits -> CF=0 */
    uint64_t rax = 0;
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
    uint8_t ah = (rax >> 8) & 0xFF;
    TEST_CHECK((ah & 0x40) == 0x40); /* ZF=1 */
    TEST_CHECK((ah & 0x01) == 0x00); /* CF=0 */

    OK(uc_close(uc));
}

static void test_x86_avx_vmaskmovps(void)
{
    uc_engine *uc;

    /*
     * Test VMASKMOVPS load (0F38 0x2C) and store (0F38 0x2E)
     *
     * vmaskmovps ymm0, ymm1, [rdx]  - conditional load
     *   C4 E2 75 2C 02
     *   VEX.256, pp=01(66), mmmmm=00010(0F38), W=0
     *   vvvv=~1=0b1110 -> ymm1 (mask)
     *   opcode=2C, modrm=02 (mod=0, reg=0, rm=2=rdx)
     *
     * vmaskmovps [rcx], ymm2, ymm3  - conditional store
     *   C4 E2 6D 2E 01
     *   VEX.256, pp=01(66), mmmmm=00010(0F38), W=0
     *   vvvv=~2=0b1101 -> ymm2 (mask)
     *   opcode=2E, modrm=01 (mod=0, reg=0, rm=1=rcx)
     */
    char code[] = {
        '\xC4', '\xE2', '\x75', '\x2C', '\x02', /* vmaskmovps ymm0, ymm1, [rdx] */
        '\xC4', '\xE2', '\x6D', '\x2E', '\x19', /* vmaskmovps [rcx], ymm2, ymm3 */
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* Source data at 0x2000: 8 floats */
    uint32_t src_data[8] = { 0x3F800000, 0x40000000, 0x40400000, 0x40800000,
                             0x40A00000, 0x40C00000, 0x40E00000, 0x41000000 };
    OK(uc_mem_write(uc, 0x2000, src_data, sizeof(src_data)));

    /* Clear destination area at 0x3000 */
    uint64_t zeros[4] = {0, 0, 0, 0};
    OK(uc_mem_write(uc, 0x3000, zeros, sizeof(zeros)));

    /* ymm1 = mask: sign bit set for elements 0, 2, 5, 7 */
    uint64_t ymm1[4] = { 0x00000000FF000000ULL, 0x0000000080000000ULL,
                          0x8000000000000000ULL, 0xC000000000000000ULL };
    /* ymm2 = mask for store: sign bit set for elements 1, 3, 4, 6 */
    uint64_t ymm2[4] = { 0x8000000000000000ULL, 0xF000000000000000ULL,
                          0x0000000080000000ULL, 0x00000000C0000000ULL };
    /* ymm3 = data to store */
    uint64_t ymm3[4] = { 0xDEADBEEFCAFEBABEULL, 0x1234567890ABCDEFULL,
                          0xAAAAAAAABBBBBBBBULL, 0xCCCCCCCCDDDDDDDDULL };
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ymm1));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, ymm2));
    OK(uc_reg_write(uc, UC_X86_REG_YMM3, ymm3));

    uint64_t rdx = 0x2000;
    uint64_t rcx = 0x3000;
    OK(uc_reg_write(uc, UC_X86_REG_RDX, &rdx));
    OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    /* Check load result in ymm0:
     * Element 0: mask bit31=1 (0xFF000000) -> load src_data[0] = 0x3F800000
     * Element 1: mask bit31=0 (0x00000000) -> 0
     * Element 2: mask bit31=1 (0x80000000) -> load src_data[2] = 0x40400000
     * Element 3: mask bit31=0 (0x00000000) -> 0
     * Element 4: mask bit31=0 (0x00000000) -> 0
     * Element 5: mask bit31=1 (0x80000000) -> load src_data[5] = 0x40C00000
     * Element 6: mask bit31=0 (0x00000000) -> 0
     * Element 7: mask bit31=1 (0xC0000000) -> load src_data[7] = 0x41000000
     */
    uint64_t ymm0[4] = {0};
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ymm0));
    TEST_CHECK(ymm0[0] == 0x000000003F800000ULL); /* elem1=0, elem0=loaded */
    TEST_CHECK(ymm0[1] == 0x0000000040400000ULL); /* elem3=0, elem2=loaded */
    TEST_CHECK(ymm0[2] == 0x40C0000000000000ULL); /* elem5=loaded, elem4=0 */
    TEST_CHECK(ymm0[3] == 0x4100000000000000ULL); /* elem7=loaded, elem6=0 */

    /* Check store result at 0x3000:
     * Element 0: mask bit31=0 (0x00000000) -> not stored (0)
     * Element 1: mask bit31=1 (0x80000000) -> store ymm3 elem1 = 0xDEADBEEF
     * Element 2: mask bit31=0 (0x00000000) -> not stored (0)
     * Element 3: mask bit31=1 (0xF0000000) -> store ymm3 elem3 = 0x12345678
     * Element 4: mask bit31=1 (0x80000000) -> store ymm3 elem4 = 0xBBBBBBBB
     * Element 5: mask bit31=0 (0x00000000) -> not stored (0)
     * Element 6: mask bit31=1 (0xC0000000) -> store ymm3 elem6 = 0xDDDDDDDD
     * Element 7: mask bit31=0 (0x00000000) -> not stored (0)
     */
    uint32_t store_result[8] = {0};
    OK(uc_mem_read(uc, 0x3000, store_result, sizeof(store_result)));
    TEST_CHECK(store_result[0] == 0x00000000); /* not stored */
    TEST_CHECK(store_result[1] == 0xDEADBEEF); /* stored */
    TEST_CHECK(store_result[2] == 0x00000000); /* not stored */
    TEST_CHECK(store_result[3] == 0x12345678); /* stored */
    TEST_CHECK(store_result[4] == 0xBBBBBBBB); /* stored */
    TEST_CHECK(store_result[5] == 0x00000000); /* not stored */
    TEST_CHECK(store_result[6] == 0xDDDDDDDD); /* stored */
    TEST_CHECK(store_result[7] == 0x00000000); /* not stored */

    OK(uc_close(uc));
}

static void test_x86_avx_vblendps_ymm(void)
{
    uc_engine *uc;

    /*
     * vblendps ymm0, ymm1, ymm2, 0xA5  (imm8=10100101b)
     *
     * C4 E3 75 0C C2 A5
     *   VEX.256, pp=01(66), mmmmm=00011(0F3A), W=0
     *   vvvv=~1=0b1110 -> ymm1
     *   opcode=0C, modrm=C2 (mod=3, reg=0, rm=2)
     *   imm8=0xA5 (bits: 1,0,1,0,0,1,0,1)
     *
     * For each dword element i:
     *   if bit i of imm8 is 1: result[i] = ymm2[i]
     *   else: result[i] = ymm1[i]
     */
    char code[] = {
        '\xC4', '\xE3', '\x75', '\x0C', '\xC2', '\xA5'
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* ymm1 = 0x11111111 per dword */
    uint64_t ymm1[4] = { 0x1111111111111111ULL, 0x1111111111111111ULL,
                          0x1111111111111111ULL, 0x1111111111111111ULL };
    /* ymm2 = 0x22222222 per dword */
    uint64_t ymm2[4] = { 0x2222222222222222ULL, 0x2222222222222222ULL,
                          0x2222222222222222ULL, 0x2222222222222222ULL };
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ymm1));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, ymm2));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    /* imm8=0xA5=10100101b
     * elem0: bit0=1 -> ymm2 = 0x22222222
     * elem1: bit1=0 -> ymm1 = 0x11111111
     * elem2: bit2=1 -> ymm2 = 0x22222222
     * elem3: bit3=0 -> ymm1 = 0x11111111
     * elem4: bit4=0 -> ymm1 = 0x11111111
     * elem5: bit5=1 -> ymm2 = 0x22222222
     * elem6: bit6=0 -> ymm1 = 0x11111111
     * elem7: bit7=1 -> ymm2 = 0x22222222
     */
    uint64_t ymm0[4] = {0};
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ymm0));
    TEST_CHECK(ymm0[0] == 0x1111111122222222ULL); /* elem1=ymm1, elem0=ymm2 */
    TEST_CHECK(ymm0[1] == 0x1111111122222222ULL); /* elem3=ymm1, elem2=ymm2 */
    TEST_CHECK(ymm0[2] == 0x2222222211111111ULL); /* elem5=ymm2, elem4=ymm1 */
    TEST_CHECK(ymm0[3] == 0x2222222211111111ULL); /* elem7=ymm2, elem6=ymm1 */

    OK(uc_close(uc));
}

static void test_x86_avx_vpalignr_ymm(void)
{
    uc_engine *uc;

    /*
     * vpalignr ymm0, ymm1, ymm2, 4  (shift by 4 bytes per lane)
     *
     * C4 E3 75 0F C2 04
     *   VEX.256, pp=01(66), mmmmm=00011(0F3A), W=0
     *   vvvv=~1=0b1110 -> ymm1
     *   opcode=0F, modrm=C2 (mod=3, reg=0, rm=2)
     *   imm8=4 (shift 4 bytes)
     *
     * Per-lane: concatenate [ymm1, ymm2] (256-bit per lane), shift right by 4 bytes
     */
    char code[] = {
        '\xC4', '\xE3', '\x75', '\x0F', '\xC2', '\x04'
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* ymm1 (high part of concat):
     * lane0 bytes 0-15: AA AA AA AA BB BB BB BB CC CC CC CC DD DD DD DD
     * lane1 bytes 16-31: EE EE EE EE FF FF FF FF 00 11 22 33 44 55 66 77 */
    uint64_t ymm1[4] = { 0xBBBBBBBBAAAAAAAAULL, 0xDDDDDDDDCCCCCCCCULL,
                          0xFFFFFFFFEEEEEEEEULL, 0x4455667700112233ULL };
    /* ymm2 (low part of concat):
     * lane0 bytes 0-15: 11 11 11 11 22 22 22 22 33 33 33 33 44 44 44 44
     * lane1 bytes 16-31: 55 55 55 55 66 66 66 66 77 77 77 77 88 88 88 88 */
    uint64_t ymm2[4] = { 0x2222222211111111ULL, 0x4444444433333333ULL,
                          0x6666666655555555ULL, 0x8888888877777777ULL };
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ymm1));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, ymm2));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    /* palignr shift=4 bytes: per lane, concat [ymm1_lane, ymm2_lane] as
     * bytes [31..16|15..0] and shift right by 4 bytes.
     * Lane 0: [DDDDDDDD CCCCCCCC BBBBBBBB AAAAAAAA | 44444444 33333333 22222222 11111111]
     *   shifted right 4 bytes:
     *   [00000000 DDDDDDDD CCCCCCCC BBBBBBBB | AAAAAAAA 44444444 33333333 22222222]
     *   result lane0 = AAAAAAAA 44444444 33333333 22222222
     *   Wait, let me re-think. palignr concatenates as [d:s] (d=ymm1, s=ymm2) then shifts right.
     *   So: [ymm1_lane | ymm2_lane] = 256-bit, shift right by 4 bytes = 32 bits.
     *   Lane 0 Q(0) and Q(1):
     *     Concat: ymm1_lane = Q(1):Q(0) = DDDDDDDDCCCCCCCC:BBBBBBBBAAAAAAAA
     *             ymm2_lane = Q(1):Q(0) = 4444444433333333:2222222211111111
     *     As 256-bit: DDDDDDDDCCCCCCCC BBBBBBBBAAAAAAAA 4444444433333333 2222222211111111
     *     Shift right 32 bits:
     *     00000000DDDDDDDD CCCCCCCCBBBBBBBB AAAAAAAA44444444 3333333322222222
     *     But palignr only returns 128-bit result (lower half of shifted):
     *     Result Q(1):Q(0) = AAAAAAAA44444444:3333333322222222
     *
     * Lane 1:
     *     ymm1_lane1 = Q(3):Q(2) = 4455667700112233:FFFFFFFFEEEEEEEE
     *     ymm2_lane1 = Q(3):Q(2) = 8888888877777777:6666666655555555
     *     Shift right 32 bits:
     *     Result Q(3):Q(2) = EEEEEEEE88888888:7777777766666666
     */
    uint64_t ymm0[4] = {0};
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ymm0));
    TEST_CHECK(ymm0[0] == 0x3333333322222222ULL);
    TEST_CHECK(ymm0[1] == 0xAAAAAAAA44444444ULL);
    TEST_CHECK(ymm0[2] == 0x7777777766666666ULL);
    TEST_CHECK(ymm0[3] == 0xEEEEEEEE88888888ULL);

    OK(uc_close(uc));
}

static void test_x86_avx_vblendvps(void)
{
    uc_engine *uc;
    uint64_t ymm0[4] = {0};

    /*
     * vblendvps ymm0, ymm1, ymm2, ymm3
     *   Blend dwords from ymm2 into ymm1 based on sign bits of ymm3.
     *   If ymm3 dword sign bit=1, take from ymm2; else take from ymm1.
     *
     * C4 E3 75 4A C2 30
     *   VEX.256, pp=01(66), mmmmm=00011(0F3A), W=0
     *   vvvv=~1=0b1110 -> ymm1
     *   opcode=4A, modrm=C2 (mod=3, reg=0, rm=2)
     *   imm8=0x30 (is4=3 -> ymm3 for mask)
     */
    char code[] = {
        '\xC4', '\xE3', '\x75', '\x4A', '\xC2', '\x30'
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* ymm1 = all 0x11111111 per dword */
    uint64_t ymm1[4] = { 0x1111111111111111ULL, 0x1111111111111111ULL,
                          0x1111111111111111ULL, 0x1111111111111111ULL };
    /* ymm2 = all 0x22222222 per dword */
    uint64_t ymm2[4] = { 0x2222222222222222ULL, 0x2222222222222222ULL,
                          0x2222222222222222ULL, 0x2222222222222222ULL };
    /* ymm3 mask: dword sign bits: 1,0,1,0, 0,1,0,1 (alternating) */
    uint64_t ymm3[4] = { 0x00000000FFFFFFFFULL, 0x00000000FFFFFFFFULL,
                          0x00000000FFFFFFFFULL, 0x00000000FFFFFFFFULL };
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ymm1));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, ymm2));
    OK(uc_reg_write(uc, UC_X86_REG_YMM3, ymm3));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ymm0));
    /* dword[0]=mask 0xFFFFFFFF (sign=1) -> from ymm2 = 0x22222222
     * dword[1]=mask 0x00000000 (sign=0) -> from ymm1 = 0x11111111 */
    TEST_CHECK(ymm0[0] == 0x1111111122222222ULL);
    TEST_CHECK(ymm0[1] == 0x1111111122222222ULL);
    TEST_CHECK(ymm0[2] == 0x1111111122222222ULL);
    TEST_CHECK(ymm0[3] == 0x1111111122222222ULL);

    OK(uc_close(uc));
}

static void test_x86_avx_vblendvpd(void)
{
    uc_engine *uc;
    uint64_t ymm0[4] = {0};

    /*
     * vblendvpd ymm0, ymm1, ymm2, ymm3
     *   Blend qwords from ymm2 into ymm1 based on sign bits of ymm3.
     *
     * C4 E3 75 4B C2 30
     *   VEX.256, pp=01(66), mmmmm=00011(0F3A), W=0
     *   vvvv=~1=0b1110 -> ymm1
     *   opcode=4B, modrm=C2 (mod=3, reg=0, rm=2)
     *   imm8=0x30 (is4=3 -> ymm3)
     */
    char code[] = {
        '\xC4', '\xE3', '\x75', '\x4B', '\xC2', '\x30'
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* ymm1 = {AAAA, BBBB, CCCC, DDDD} */
    uint64_t ymm1[4] = { 0xAAAAAAAAAAAAAAAAULL, 0xBBBBBBBBBBBBBBBBULL,
                          0xCCCCCCCCCCCCCCCCULL, 0xDDDDDDDDDDDDDDDDULL };
    /* ymm2 = {1111, 2222, 3333, 4444} */
    uint64_t ymm2[4] = { 0x1111111111111111ULL, 0x2222222222222222ULL,
                          0x3333333333333333ULL, 0x4444444444444444ULL };
    /* ymm3 mask: qword[0] sign=1, [1] sign=0, [2] sign=1, [3] sign=0 */
    uint64_t ymm3[4] = { 0x8000000000000000ULL, 0x0000000000000000ULL,
                          0xFFFFFFFFFFFFFFFFULL, 0x7FFFFFFFFFFFFFFFULL };
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ymm1));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, ymm2));
    OK(uc_reg_write(uc, UC_X86_REG_YMM3, ymm3));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ymm0));
    /* qword[0]: mask sign=1 -> from ymm2 = 0x1111111111111111 */
    TEST_CHECK(ymm0[0] == 0x1111111111111111ULL);
    /* qword[1]: mask sign=0 -> from ymm1 = 0xBBBBBBBBBBBBBBBB */
    TEST_CHECK(ymm0[1] == 0xBBBBBBBBBBBBBBBBULL);
    /* qword[2]: mask sign=1 -> from ymm2 = 0x3333333333333333 */
    TEST_CHECK(ymm0[2] == 0x3333333333333333ULL);
    /* qword[3]: mask sign=0 -> from ymm1 = 0xDDDDDDDDDDDDDDDD */
    TEST_CHECK(ymm0[3] == 0xDDDDDDDDDDDDDDDDULL);

    OK(uc_close(uc));
}

static void test_x86_avx_vpblendvb(void)
{
    uc_engine *uc;
    uint64_t ymm0[4] = {0};

    /*
     * vpblendvb ymm0, ymm1, ymm2, ymm3
     *   Blend bytes from ymm2 into ymm1 based on high bit of each byte in ymm3.
     *
     * C4 E3 75 4C C2 30
     *   VEX.256, pp=01(66), mmmmm=00011(0F3A), W=0
     *   vvvv=~1=0b1110 -> ymm1
     *   opcode=4C, modrm=C2 (mod=3, reg=0, rm=2)
     *   imm8=0x30 (is4=3 -> ymm3)
     */
    char code[] = {
        '\xC4', '\xE3', '\x75', '\x4C', '\xC2', '\x30'
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* ymm1 = all 0xAA bytes */
    uint64_t ymm1[4] = { 0xAAAAAAAAAAAAAAAAULL, 0xAAAAAAAAAAAAAAAAULL,
                          0xAAAAAAAAAAAAAAAAULL, 0xAAAAAAAAAAAAAAAAULL };
    /* ymm2 = all 0x55 bytes */
    uint64_t ymm2[4] = { 0x5555555555555555ULL, 0x5555555555555555ULL,
                          0x5555555555555555ULL, 0x5555555555555555ULL };
    /* ymm3 mask: alternating 0xFF(sign=1)/0x00(sign=0) per byte */
    uint64_t ymm3[4] = { 0x00FF00FF00FF00FFULL, 0x00FF00FF00FF00FFULL,
                          0x00FF00FF00FF00FFULL, 0x00FF00FF00FF00FFULL };
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ymm1));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, ymm2));
    OK(uc_reg_write(uc, UC_X86_REG_YMM3, ymm3));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ymm0));
    /* byte[0]: mask 0xFF (sign=1) -> from ymm2 = 0x55
     * byte[1]: mask 0x00 (sign=0) -> from ymm1 = 0xAA
     * Pattern: 0xAA55AA55... */
    TEST_CHECK(ymm0[0] == 0xAA55AA55AA55AA55ULL);
    TEST_CHECK(ymm0[1] == 0xAA55AA55AA55AA55ULL);
    TEST_CHECK(ymm0[2] == 0xAA55AA55AA55AA55ULL);
    TEST_CHECK(ymm0[3] == 0xAA55AA55AA55AA55ULL);

    OK(uc_close(uc));
}

static void test_x86_avx_vpmovsxbw_ymm(void)
{
    uc_engine *uc;
    uint64_t ymm0[4] = {0};

    /*
     * vpmovsxbw ymm0, xmm1
     *   Sign-extend 16 bytes from xmm1 into 16 words in ymm0.
     *
     * C4 E2 7D 20 C1
     *   VEX.256, pp=01(66), mmmmm=00010(0F38), W=0
     *   vvvv=1111 (unused for 2-op)
     *   opcode=20, modrm=C1 (mod=3, reg=0, rm=1)
     */
    char code[] = {
        '\xC4', '\xE2', '\x7D', '\x20', '\xC1'
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* xmm1 = 16 bytes: 0x01, 0xFF, 0x02, 0xFE, 0x03, 0xFD, 0x04, 0xFC,
     *                   0x05, 0xFB, 0x06, 0xFA, 0x07, 0xF9, 0x08, 0xF8
     * (little-endian qwords) */
    uint64_t xmm1[2] = { 0xFC04FD03FE02FF01ULL, 0xF808F907FA06FB05ULL };
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, xmm1));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ymm0));
    /* Byte 0x01 -> word 0x0001, 0xFF -> 0xFFFF, 0x02 -> 0x0002, 0xFE -> 0xFFFE */
    TEST_CHECK(ymm0[0] == 0xFFFE0002FFFF0001ULL);
    /* 0x03 -> 0x0003, 0xFD -> 0xFFFD, 0x04 -> 0x0004, 0xFC -> 0xFFFC */
    TEST_CHECK(ymm0[1] == 0xFFFC0004FFFD0003ULL);
    /* 0x05 -> 0x0005, 0xFB -> 0xFFFB, 0x06 -> 0x0006, 0xFA -> 0xFFFA */
    TEST_CHECK(ymm0[2] == 0xFFFA0006FFFB0005ULL);
    /* 0x07 -> 0x0007, 0xF9 -> 0xFFF9, 0x08 -> 0x0008, 0xF8 -> 0xFFF8 */
    TEST_CHECK(ymm0[3] == 0xFFF80008FFF90007ULL);

    OK(uc_close(uc));
}

static void test_x86_avx_vpmovzxbd_ymm(void)
{
    uc_engine *uc;
    uint64_t ymm0[4] = {0};

    /*
     * vpmovzxbd ymm0, xmm1
     *   Zero-extend 8 bytes from xmm1 into 8 dwords in ymm0.
     *
     * C4 E2 7D 31 C1
     *   VEX.256, pp=01(66), mmmmm=00010(0F38), W=0
     *   vvvv=1111 (unused)
     *   opcode=31, modrm=C1 (mod=3, reg=0, rm=1)
     */
    char code[] = {
        '\xC4', '\xE2', '\x7D', '\x31', '\xC1'
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* xmm1 lower 64 bits = 8 bytes: 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 */
    uint64_t xmm1[2] = { 0x8877665544332211ULL, 0 };
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, xmm1));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ymm0));
    /* byte 0x11 -> dword 0x00000011, 0x22 -> 0x00000022, etc. */
    TEST_CHECK(ymm0[0] == 0x0000002200000011ULL);
    TEST_CHECK(ymm0[1] == 0x0000004400000033ULL);
    TEST_CHECK(ymm0[2] == 0x0000006600000055ULL);
    TEST_CHECK(ymm0[3] == 0x0000008800000077ULL);

    OK(uc_close(uc));
}

static void test_x86_avx2_vpbroadcastd(void)
{
    uc_engine *uc;
    uint64_t ymm0[4] = {0};

    /*
     * vpbroadcastd ymm0, xmm1
     *   Broadcast dword[0] of xmm1 to all dwords in ymm0.
     *
     * C4 E2 7D 58 C1
     *   VEX.256, pp=01(66), mmmmm=00010(0F38), W=0
     *   vvvv=1111 (unused)
     *   opcode=58, modrm=C1 (mod=3, reg=0, rm=1)
     */
    char code[] = {
        '\xC4', '\xE2', '\x7D', '\x58', '\xC1'
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    uint64_t xmm1[2] = { 0xDEADBEEF12345678ULL, 0 };
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, xmm1));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ymm0));
    /* dword[0] = 0x12345678 broadcast to all 8 dwords */
    TEST_CHECK(ymm0[0] == 0x1234567812345678ULL);
    TEST_CHECK(ymm0[1] == 0x1234567812345678ULL);
    TEST_CHECK(ymm0[2] == 0x1234567812345678ULL);
    TEST_CHECK(ymm0[3] == 0x1234567812345678ULL);

    OK(uc_close(uc));
}

static void test_x86_avx2_vperm2i128(void)
{
    uc_engine *uc;
    uint64_t ymm0[4] = {0};

    /*
     * vperm2i128 ymm0, ymm1, ymm2, 0x31
     *   Same as vperm2f128 but integer domain (AVX2).
     *
     * C4 E3 75 46 C2 31
     *   VEX.256, pp=01(66), mmmmm=00011(0F3A), W=0
     *   vvvv=~1=0b1110 -> ymm1
     *   opcode=46, modrm=C2 (mod=3, reg=0, rm=2)
     *   imm8=0x31
     */
    char code[] = {
        '\xC4', '\xE3', '\x75', '\x46', '\xC2', '\x31'
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    uint64_t ymm1[4] = { 0x1111111122222222ULL, 0x3333333344444444ULL,
                          0xAAAAAAAABBBBBBBBULL, 0xCCCCCCCCDDDDDDDDULL };
    uint64_t ymm2[4] = { 0x5555555566666666ULL, 0x7777777788888888ULL,
                          0xEEEEEEEEFFFFFFFFULL, 0x9999999900000000ULL };
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ymm1));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, ymm2));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ymm0));
    /* imm8=0x31: low=src1 lane 1, high=src2 lane 1 */
    TEST_CHECK(ymm0[0] == 0xAAAAAAAABBBBBBBBULL);
    TEST_CHECK(ymm0[1] == 0xCCCCCCCCDDDDDDDDULL);
    TEST_CHECK(ymm0[2] == 0xEEEEEEEEFFFFFFFFULL);
    TEST_CHECK(ymm0[3] == 0x9999999900000000ULL);

    OK(uc_close(uc));
}

static void test_x86_avx2_vpermd(void)
{
    uc_engine *uc;
    uint64_t ymm0[4] = {0};

    /*
     * vpermd ymm0, ymm1, ymm2
     *   Permute dwords in ymm2 using indices in ymm1, store in ymm0.
     *
     * C4 E2 75 36 C2
     *   VEX.256, pp=01(66), mmmmm=00010(0F38), W=0
     *   vvvv=~1=0b1110 -> ymm1 (index)
     *   opcode=36, modrm=C2 (mod=3, reg=0, rm=2) -> dest=ymm0, src=ymm2
     */
    char code[] = {
        '\xC4', '\xE2', '\x75', '\x36', '\xC2'
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* ymm2 = source data: dwords 0x10,0x20,...,0x80 */
    uint64_t ymm2[4] = {
        0x0000002000000010ULL,  /* dword[1]=0x20, dword[0]=0x10 */
        0x0000004000000030ULL,  /* dword[3]=0x40, dword[2]=0x30 */
        0x0000006000000050ULL,  /* dword[5]=0x60, dword[4]=0x50 */
        0x0000008000000070ULL   /* dword[7]=0x80, dword[6]=0x70 */
    };
    /* ymm1 = index vector: pick dwords in reverse order (7,6,5,4,3,2,1,0) */
    uint64_t ymm1[4] = {
        0x0000000600000007ULL,  /* idx[1]=6, idx[0]=7 */
        0x0000000400000005ULL,  /* idx[3]=4, idx[2]=5 */
        0x0000000200000003ULL,  /* idx[5]=2, idx[4]=3 */
        0x0000000000000001ULL   /* idx[7]=0, idx[6]=1 */
    };
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ymm1));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, ymm2));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ymm0));
    /* Result: reversed dwords: 0x80,0x70,0x60,0x50,0x40,0x30,0x20,0x10 */
    TEST_CHECK(ymm0[0] == 0x0000007000000080ULL);
    TEST_CHECK(ymm0[1] == 0x0000005000000060ULL);
    TEST_CHECK(ymm0[2] == 0x0000003000000040ULL);
    TEST_CHECK(ymm0[3] == 0x0000001000000020ULL);

    OK(uc_close(uc));
}

static void test_x86_avx2_vpermq(void)
{
    uc_engine *uc;
    uint64_t ymm0[4] = {0};

    /*
     * vpermq ymm0, ymm1, 0x1B
     *   Permute qwords in ymm1 using imm8=0x1B (00_01_10_11 = 0,1,2,3 reversed)
     *   Result: q[0]=q[3], q[1]=q[2], q[2]=q[1], q[3]=q[0]
     *
     * C4 E3 FD 00 C1 1B
     *   VEX.256, pp=01(66), mmmmm=00011(0F3A), W=1
     *   vvvv=1111 (unused)
     *   opcode=00, modrm=C1 (mod=3, reg=0, rm=1)
     *   imm8=0x1B
     */
    char code[] = {
        '\xC4', '\xE3', '\xFD', '\x00', '\xC1', '\x1B'
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* ymm1 = source: qwords 0xAA, 0xBB, 0xCC, 0xDD */
    uint64_t ymm1[4] = { 0xAAULL, 0xBBULL, 0xCCULL, 0xDDULL };
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ymm1));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ymm0));
    /* imm8=0x1B: q[0]=src[3]=0xDD, q[1]=src[2]=0xCC, q[2]=src[1]=0xBB, q[3]=src[0]=0xAA */
    TEST_CHECK(ymm0[0] == 0xDDULL);
    TEST_CHECK(ymm0[1] == 0xCCULL);
    TEST_CHECK(ymm0[2] == 0xBBULL);
    TEST_CHECK(ymm0[3] == 0xAAULL);

    OK(uc_close(uc));
}

static void test_x86_avx2_vpsllvd(void)
{
    uc_engine *uc;
    uint64_t ymm0[4] = {0};

    /*
     * vpsllvd ymm0, ymm1, ymm2
     *   Variable left shift each dword in ymm1 by corresponding count in ymm2.
     *
     * C4 E2 75 47 C2
     *   VEX.256, pp=01(66), mmmmm=00010(0F38), W=0
     *   vvvv=~1=0b1110 -> ymm1 (data)
     *   opcode=47, modrm=C2 (mod=3, reg=0, rm=2) -> dest=ymm0, counts=ymm2
     */
    char code[] = {
        '\xC4', '\xE2', '\x75', '\x47', '\xC2'
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* ymm1 = data: all dwords = 0x00000001 */
    uint64_t ymm1[4] = {
        0x0000000100000001ULL,
        0x0000000100000001ULL,
        0x0000000100000001ULL,
        0x0000000100000001ULL
    };
    /* ymm2 = shift counts: 0,1,2,3,4,8,16,32 */
    uint64_t ymm2[4] = {
        0x0000000100000000ULL,  /* count[0]=0, count[1]=1 */
        0x0000000300000002ULL,  /* count[2]=2, count[3]=3 */
        0x0000000800000004ULL,  /* count[4]=4, count[5]=8 */
        0x0000002000000010ULL   /* count[6]=16, count[7]=32 */
    };
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ymm1));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, ymm2));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ymm0));
    /* 1<<0=1, 1<<1=2, 1<<2=4, 1<<3=8, 1<<4=16, 1<<8=256, 1<<16=65536, 1<<32=0 */
    TEST_CHECK(ymm0[0] == 0x0000000200000001ULL);
    TEST_CHECK(ymm0[1] == 0x0000000800000004ULL);
    TEST_CHECK(ymm0[2] == 0x0000010000000010ULL);
    TEST_CHECK(ymm0[3] == 0x0000000000010000ULL);

    OK(uc_close(uc));
}

static void test_x86_avx2_vpacksswb_ymm(void)
{
    uc_engine *uc;
    uint64_t ymm0[4] = {0};

    /*
     * vpacksswb ymm0, ymm1, ymm2
     *   Per-lane: pack words from ymm1 and ymm2 into signed bytes.
     *   Lane 0: pack ymm1[0:7] then ymm2[0:7] into bytes 0-15
     *   Lane 1: pack ymm1[8:15] then ymm2[8:15] into bytes 16-31
     *
     * C5 F5 63 C2 = VEX.256.66.0F 63 /r
     *   VEX.256, pp=01(66), map=0F, W=0
     *   vvvv=~1 -> ymm1, modrm=C2 (mod=3, reg=0, rm=2)
     */
    char code[] = {
        '\xC5', '\xF5', '\x63', '\xC2'
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* ymm1 (d): lane0 words = 1,2,3,4,5,6,7,8; lane1 = 0x100 repeated (clamp) */
    uint64_t ymm1[4] = {
        0x0002000100040003ULL,  /* W(3)=2, W(2)=1, W(1)=4, W(0)=3 -- wait */
        0x0006000500080007ULL,
        0x0100010001000100ULL,  /* 256 -> clamps to 127 */
        0x0100010001000100ULL
    };
    /* Actually, let me use simpler values. Words in memory order:
     * ymm1 W(0)=1, W(1)=2, ..., W(7)=8 for lane 0
     * ymm1 W(8)=0x100, all lane1 words = 0x100 (saturates to 0x7F)
     */
    ymm1[0] = 0x0002000100040003ULL; /* In little-endian: W(0)=3, W(1)=4, W(2)=1, W(3)=2 */
    /* Let me use very clear values instead */
    ymm1[0] = (uint64_t)0x0001 | ((uint64_t)0x0002 << 16) |
              ((uint64_t)0x0003 << 32) | ((uint64_t)0x0004 << 48);
    ymm1[1] = (uint64_t)0x0005 | ((uint64_t)0x0006 << 16) |
              ((uint64_t)0x0007 << 32) | ((uint64_t)0x0008 << 48);
    ymm1[2] = (uint64_t)0x0100 | ((uint64_t)0x0100 << 16) |
              ((uint64_t)0x0100 << 32) | ((uint64_t)0x0100 << 48);
    ymm1[3] = (uint64_t)0x0100 | ((uint64_t)0x0100 << 16) |
              ((uint64_t)0x0100 << 32) | ((uint64_t)0x0100 << 48);

    /* ymm2 (s): lane0 words = 0x10..0x17; lane1 = 0xFF00 repeated (clamps to -128=0x80) */
    uint64_t ymm2[4];
    ymm2[0] = (uint64_t)0x0010 | ((uint64_t)0x0011 << 16) |
              ((uint64_t)0x0012 << 32) | ((uint64_t)0x0013 << 48);
    ymm2[1] = (uint64_t)0x0014 | ((uint64_t)0x0015 << 16) |
              ((uint64_t)0x0016 << 32) | ((uint64_t)0x0017 << 48);
    ymm2[2] = (uint64_t)0xFF00 | ((uint64_t)0xFF00 << 16) |
              ((uint64_t)0xFF00 << 32) | ((uint64_t)0xFF00 << 48);
    ymm2[3] = (uint64_t)0xFF00 | ((uint64_t)0xFF00 << 16) |
              ((uint64_t)0xFF00 << 32) | ((uint64_t)0xFF00 << 48);

    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ymm1));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, ymm2));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ymm0));
    /*
     * Per-lane result:
     * Lane 0 bytes 0-7: satsb(d lane0) = 1,2,3,4,5,6,7,8
     * Lane 0 bytes 8-15: satsb(s lane0) = 0x10..0x17
     * Lane 1 bytes 16-23: satsb(d lane1) = 0x7F * 8 (0x100 clamps to 127)
     * Lane 1 bytes 24-31: satsb(s lane1) = 0x80 * 8 (0xFF00=-256 clamps to -128)
     */
    TEST_CHECK(ymm0[0] == 0x0807060504030201ULL);
    TEST_CHECK(ymm0[1] == 0x1716151413121110ULL);
    TEST_CHECK(ymm0[2] == 0x7F7F7F7F7F7F7F7FULL);
    TEST_CHECK(ymm0[3] == 0x8080808080808080ULL);

    OK(uc_close(uc));
}

static void test_x86_avx2_vpgatherdd(void)
{
    uc_engine *uc;
    uint64_t xmm0[2] = {0};

    /*
     * vpgatherdd xmm0, [rcx + xmm2*4], xmm1
     *   Gather dwords from memory using dword indices in xmm2.
     *   For each element i where mask xmm1[i] MSB is set:
     *     xmm0[i] = mem[rcx + xmm2[i]*4]
     *   After: xmm1 is zeroed.
     *
     * Encoding: C4 E2 71 90 04 91
     *   C4 = 3-byte VEX prefix
     *   E2 = ~R=1 ~X=1 ~B=1 mmmmm=00010 (0F38)
     *   71 = W=0 ~vvvv=0111->vvvv=1000... wait
     *
     * Let me use: vpgatherdd xmm0, [rcx + xmm2*4], xmm1
     *   VEX.128.66.0F38.W0 90 /vsib
     *   dest=xmm0 (modrm.reg=0), mask=xmm1 (vvvv=1), index=xmm2 (SIB.index=2)
     *   base=rcx (SIB.base=1), scale=4 (SIB.ss=10)
     *
     *   3-byte VEX: C4 [RXBmmmmm] [WvvvvLpp]
     *   R=1,X=1,B=1 -> ~R=0,~X=0,~B=0 -> first byte = 11100010 = E2
     *   W=0, vvvv=~1=1110, L=0, pp=01 -> 01110001 = 71
     *   opcode=90
     *   modrm: mod=00, reg=000, rm=100(SIB) -> 00000100 = 04
     *   SIB: ss=10, index=010, base=001 -> 10010001 = 91
     */
    char code[] = {
        '\xC4', '\xE2', '\x71', '\x90', '\x04', '\x91'
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* Set up a dword array at address 0x2000: [10, 20, 30, 40, 50, 60, 70, 80] */
    uint32_t data[] = { 10, 20, 30, 40, 50, 60, 70, 80 };
    OK(uc_mem_write(uc, 0x2000, data, sizeof(data)));

    /* rcx = base address = 0x2000 */
    uint64_t rcx = 0x2000;
    OK(uc_reg_write(uc, UC_X86_REG_RCX, &rcx));

    /* xmm2 = index vector: [2, 0, 5, 7] (gather data[2], data[0], data[5], data[7]) */
    uint64_t xmm2[2] = {
        (uint64_t)2 | ((uint64_t)0 << 32),     /* idx[0]=2, idx[1]=0 */
        (uint64_t)5 | ((uint64_t)7 << 32)      /* idx[2]=5, idx[3]=7 */
    };
    OK(uc_reg_write(uc, UC_X86_REG_XMM2, xmm2));

    /* xmm1 = mask: all MSBs set (all elements active) */
    uint64_t xmm1[2] = { 0x8000000080000000ULL, 0x8000000080000000ULL };
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, xmm1));

    /* xmm0 = initial dest (should be overwritten) */
    uint64_t xmm0_init[2] = { 0xDEADDEADDEADDEADULL, 0xDEADDEADDEADDEADULL };
    OK(uc_reg_write(uc, UC_X86_REG_XMM0, xmm0_init));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_XMM0, xmm0));
    /* Result: data[2]=30, data[0]=10, data[5]=60, data[7]=80 */
    TEST_CHECK((uint32_t)(xmm0[0]) == 30);
    TEST_CHECK((uint32_t)(xmm0[0] >> 32) == 10);
    TEST_CHECK((uint32_t)(xmm0[1]) == 60);
    TEST_CHECK((uint32_t)(xmm0[1] >> 32) == 80);

    /* Mask should be zeroed */
    uint64_t mask_result[2] = {0};
    OK(uc_reg_read(uc, UC_X86_REG_XMM1, mask_result));
    TEST_CHECK(mask_result[0] == 0);
    TEST_CHECK(mask_result[1] == 0);

    OK(uc_close(uc));
}

static void test_x86_avx_vroundss(void)
{
    uc_engine *uc;
    uint64_t xmm0[2] = {0};

    /*
     * vroundss xmm0, xmm1, xmm2, 1
     *   Round xmm2[0] toward -inf, copy xmm1 upper elements to xmm0.
     *
     * C4 E3 71 0A C2 01
     *   VEX.128.66.0F3A.WIG 0A /r ib
     *   vvvv=~1=1110 -> xmm1, reg=0 (dest=xmm0), rm=2 (src=xmm2)
     *   imm8=0x01 (round toward -inf)
     */
    char code[] = {
        '\xC4', '\xE3', '\x71', '\x0A', '\xC2', '\x01'
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* xmm1: upper elements should be preserved */
    float f1_vals[4] = { 99.0f, 1.0f, 2.0f, 3.0f };
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, f1_vals));

    /* xmm2: element 0 = 2.7f (should round to 2.0 toward -inf) */
    float f2_vals[4] = { 2.7f, 0.0f, 0.0f, 0.0f };
    OK(uc_reg_write(uc, UC_X86_REG_XMM2, f2_vals));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    float result[4];
    OK(uc_reg_read(uc, UC_X86_REG_XMM0, result));
    /* element 0: floor(2.7) = 2.0, elements 1-3: from xmm1 (1.0, 2.0, 3.0) */
    TEST_CHECK(result[0] == 2.0f);
    TEST_CHECK(result[1] == 1.0f);
    TEST_CHECK(result[2] == 2.0f);
    TEST_CHECK(result[3] == 3.0f);

    OK(uc_close(uc));
}

static void test_x86_avx2_vpblendd(void)
{
    uc_engine *uc;
    uint64_t xmm0[2] = {0};

    /*
     * vpblendd xmm0, xmm1, xmm2, 0x05
     *   Blend: bits 0,2 from xmm2 (mask=0101), bits 1,3 from xmm1.
     *
     * C4 E3 71 02 C2 05
     *   VEX.128.66.0F3A.W0 02 /r ib
     *   vvvv=~1=1110 -> xmm1, modrm=C2 (reg=0, rm=2), imm8=0x05
     */
    char code[] = {
        '\xC4', '\xE3', '\x71', '\x02', '\xC2', '\x05'
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    uint64_t xmm1[2] = { 0x1111111122222222ULL, 0x3333333344444444ULL };
    uint64_t xmm2[2] = { 0xAAAAAAAABBBBBBBBULL, 0xCCCCCCCCDDDDDDDDULL };
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, xmm1));
    OK(uc_reg_write(uc, UC_X86_REG_XMM2, xmm2));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_XMM0, xmm0));
    /* imm8=0x05 = 0b0101: dword[0] from xmm2, dword[1] from xmm1,
     * dword[2] from xmm2, dword[3] from xmm1 */
    TEST_CHECK((uint32_t)(xmm0[0]) == 0xBBBBBBBBU);       /* dword[0] from xmm2 */
    TEST_CHECK((uint32_t)(xmm0[0] >> 32) == 0x11111111U);  /* dword[1] from xmm1 */
    TEST_CHECK((uint32_t)(xmm0[1]) == 0xDDDDDDDDU);        /* dword[2] from xmm2 */
    TEST_CHECK((uint32_t)(xmm0[1] >> 32) == 0x33333333U);  /* dword[3] from xmm1 */

    OK(uc_close(uc));
}

/* Test VFMADD231PS xmm0, xmm1, xmm2:
 * xmm0 = xmm1 * xmm2 + xmm0
 * With xmm0={1,1,1,1}, xmm1={2,3,4,5}, xmm2={10,10,10,10}
 * Result: {2*10+1, 3*10+1, 4*10+1, 5*10+1} = {21,31,41,51}
 */
static void test_x86_fma_vfmadd231ps(void)
{
    uc_engine *uc;

    /*
     * vfmadd231ps xmm0, xmm1, xmm2
     * VEX.128.66.0F38.W0 B8 /r
     * C4 E2 71 B8 C2
     */
    char code[] = { '\xC4', '\xE2', '\x71', '\xB8', '\xC2' };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    float xmm0_in[4] = { 1.0f, 1.0f, 1.0f, 1.0f };
    float xmm1_in[4] = { 2.0f, 3.0f, 4.0f, 5.0f };
    float xmm2_in[4] = { 10.0f, 10.0f, 10.0f, 10.0f };
    OK(uc_reg_write(uc, UC_X86_REG_XMM0, xmm0_in));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, xmm1_in));
    OK(uc_reg_write(uc, UC_X86_REG_XMM2, xmm2_in));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    float xmm0_out[4];
    OK(uc_reg_read(uc, UC_X86_REG_XMM0, xmm0_out));
    /* xmm0 = xmm1 * xmm2 + xmm0 = {21, 31, 41, 51} */
    TEST_CHECK(xmm0_out[0] == 21.0f);
    TEST_CHECK(xmm0_out[1] == 31.0f);
    TEST_CHECK(xmm0_out[2] == 41.0f);
    TEST_CHECK(xmm0_out[3] == 51.0f);

    OK(uc_close(uc));
}

/* Test VFNMSUB213SD xmm0, xmm1, xmm2:
 * xmm0[0] = -(xmm1[0] * xmm0[0]) - xmm2[0]
 * With xmm0={3.0,99.0}, xmm1={4.0,99.0}, xmm2={5.0,99.0}
 * Result[0] = -(4*3) - 5 = -17.0, Result[1] = 99.0 (unchanged)
 */
static void test_x86_fma_vfnmsub213sd(void)
{
    uc_engine *uc;

    /*
     * vfnmsub213sd xmm0, xmm1, xmm2
     * VEX.LIG.66.0F38.W1 AF /r
     * C4 E2 F1 AF C2
     */
    char code[] = { '\xC4', '\xE2', '\xF1', '\xAF', '\xC2' };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    double xmm0_in[2] = { 3.0, 99.0 };
    double xmm1_in[2] = { 4.0, 99.0 };
    double xmm2_in[2] = { 5.0, 99.0 };
    OK(uc_reg_write(uc, UC_X86_REG_XMM0, xmm0_in));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, xmm1_in));
    OK(uc_reg_write(uc, UC_X86_REG_XMM2, xmm2_in));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    double xmm0_out[2];
    OK(uc_reg_read(uc, UC_X86_REG_XMM0, xmm0_out));
    /* 213 form: result = -(vvvv * dest) - src = -(4*3) - 5 = -17 */
    TEST_CHECK(xmm0_out[0] == -17.0);
    TEST_CHECK(xmm0_out[1] == 99.0);

    OK(uc_close(uc));
}

/* Test VCVTPS2PH and VCVTPH2PS round-trip */
static void test_x86_f16c(void)
{
    uc_engine *uc;

    /*
     * vcvtps2ph xmm1, xmm0, 0   ; convert 4 floats to 4 half-floats
     * VEX.128.66.0F3A.W0 1D /r ib
     * C4 E3 79 1D C1 00
     *
     * vcvtph2ps xmm2, xmm1       ; convert 4 half-floats back to 4 floats
     * VEX.128.66.0F38.W0 13 /r
     * C4 E2 79 13 D1
     */
    char code[] = {
        '\xC4', '\xE3', '\x79', '\x1D', '\xC1', '\x00',  /* vcvtps2ph xmm1, xmm0, 0 */
        '\xC4', '\xE2', '\x79', '\x13', '\xD1'            /* vcvtph2ps xmm2, xmm1 */
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    float xmm0_in[4] = { 1.0f, 2.0f, -0.5f, 65504.0f };  /* values representable in float16 */
    OK(uc_reg_write(uc, UC_X86_REG_XMM0, xmm0_in));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    float xmm2_out[4];
    OK(uc_reg_read(uc, UC_X86_REG_XMM2, xmm2_out));
    /* Round-trip should preserve these values exactly */
    TEST_CHECK(xmm2_out[0] == 1.0f);
    TEST_CHECK(xmm2_out[1] == 2.0f);
    TEST_CHECK(xmm2_out[2] == -0.5f);
    TEST_CHECK(xmm2_out[3] == 65504.0f);

    OK(uc_close(uc));
}

/* Test VPHADDW ymm0, ymm1, ymm2 (per-lane horizontal add) */
static void test_x86_avx2_vphaddw_ymm(void)
{
    uc_engine *uc;

    /*
     * vphaddw ymm0, ymm1, ymm2
     * VEX.256.66.0F38.WIG 01 /r  (phaddw)
     * C4 E2 75 01 C2
     *   vvvv=~1=1110->ymm1, modrm=C2 (reg=0, rm=2)
     */
    char code[] = { '\xC4', '\xE2', '\x75', '\x01', '\xC2' };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* ymm1: lane0 words = {1,2,3,4,5,6,7,8}, lane1 = {9,10,11,12,13,14,15,16} */
    uint16_t ymm1_w[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    /* ymm2: lane0 words = {10,20,30,40,50,60,70,80}, lane1 = {100,200,300,400,500,600,700,800} */
    uint16_t ymm2_w[16] = {10,20,30,40,50,60,70,80,100,200,300,400,500,600,700,800};
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ymm1_w));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, ymm2_w));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    uint16_t ymm0_out[16];
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ymm0_out));
    /* Per-lane horizontal add:
     * Lane 0: hadd(ymm1[0:7]) = {1+2,3+4,5+6,7+8} = {3,7,11,15}
     *         hadd(ymm2[0:7]) = {10+20,30+40,50+60,70+80} = {30,70,110,150}
     * Lane 1: hadd(ymm1[8:15]) = {9+10,11+12,13+14,15+16} = {19,23,27,31}
     *         hadd(ymm2[8:15]) = {100+200,300+400,500+600,700+800} = {300,700,1100,1500}
     */
    TEST_CHECK(ymm0_out[0] == 3);
    TEST_CHECK(ymm0_out[1] == 7);
    TEST_CHECK(ymm0_out[2] == 11);
    TEST_CHECK(ymm0_out[3] == 15);
    TEST_CHECK(ymm0_out[4] == 30);
    TEST_CHECK(ymm0_out[5] == 70);
    TEST_CHECK(ymm0_out[6] == 110);
    TEST_CHECK(ymm0_out[7] == 150);
    TEST_CHECK(ymm0_out[8] == 19);
    TEST_CHECK(ymm0_out[9] == 23);
    TEST_CHECK(ymm0_out[10] == 27);
    TEST_CHECK(ymm0_out[11] == 31);
    TEST_CHECK(ymm0_out[12] == 300);
    TEST_CHECK(ymm0_out[13] == 700);
    TEST_CHECK(ymm0_out[14] == 1100);
    TEST_CHECK(ymm0_out[15] == 1500);

    OK(uc_close(uc));
}

/* Test VFMADD132PS xmm0, xmm1, xmm2 (132 form):
 * xmm0 = xmm0 * xmm2 + xmm1  (a=reg, b=src, c=vvvv → result = a*b + c)
 * xmm0={2,3,4,5}, xmm1={100,200,300,400}, xmm2={10,10,10,10}
 * Result = {2*10+100, 3*10+200, 4*10+300, 5*10+400} = {120,230,340,450}
 */
static void test_x86_fma_vfmadd132ps(void)
{
    uc_engine *uc;

    /*
     * vfmadd132ps xmm0, xmm1, xmm2
     * VEX.128.66.0F38.W0 98 /r
     * C4 E2 71 98 C2
     */
    char code[] = { '\xC4', '\xE2', '\x71', '\x98', '\xC2' };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    float xmm0_in[4] = { 2.0f, 3.0f, 4.0f, 5.0f };
    float xmm1_in[4] = { 100.0f, 200.0f, 300.0f, 400.0f };
    float xmm2_in[4] = { 10.0f, 10.0f, 10.0f, 10.0f };
    OK(uc_reg_write(uc, UC_X86_REG_XMM0, xmm0_in));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, xmm1_in));
    OK(uc_reg_write(uc, UC_X86_REG_XMM2, xmm2_in));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    float xmm0_out[4];
    OK(uc_reg_read(uc, UC_X86_REG_XMM0, xmm0_out));
    /* 132 form: result = reg * src + vvvv = xmm0 * xmm2 + xmm1 */
    TEST_CHECK(xmm0_out[0] == 120.0f);
    TEST_CHECK(xmm0_out[1] == 230.0f);
    TEST_CHECK(xmm0_out[2] == 340.0f);
    TEST_CHECK(xmm0_out[3] == 450.0f);

    OK(uc_close(uc));
}

/* Test VFMADD213PS xmm0, xmm1, xmm2 (213 form):
 * xmm0 = xmm1 * xmm0 + xmm2  (a=vvvv, b=reg, c=src → result = a*b + c)
 * xmm0={3,4,5,6}, xmm1={10,10,10,10}, xmm2={1,2,3,4}
 * Result = {10*3+1, 10*4+2, 10*5+3, 10*6+4} = {31,42,53,64}
 */
static void test_x86_fma_vfmadd213ps(void)
{
    uc_engine *uc;

    /*
     * vfmadd213ps xmm0, xmm1, xmm2
     * VEX.128.66.0F38.W0 A8 /r
     * C4 E2 71 A8 C2
     */
    char code[] = { '\xC4', '\xE2', '\x71', '\xA8', '\xC2' };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    float xmm0_in[4] = { 3.0f, 4.0f, 5.0f, 6.0f };
    float xmm1_in[4] = { 10.0f, 10.0f, 10.0f, 10.0f };
    float xmm2_in[4] = { 1.0f, 2.0f, 3.0f, 4.0f };
    OK(uc_reg_write(uc, UC_X86_REG_XMM0, xmm0_in));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, xmm1_in));
    OK(uc_reg_write(uc, UC_X86_REG_XMM2, xmm2_in));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    float xmm0_out[4];
    OK(uc_reg_read(uc, UC_X86_REG_XMM0, xmm0_out));
    /* 213 form: result = vvvv * reg + src = xmm1 * xmm0 + xmm2 */
    TEST_CHECK(xmm0_out[0] == 31.0f);
    TEST_CHECK(xmm0_out[1] == 42.0f);
    TEST_CHECK(xmm0_out[2] == 53.0f);
    TEST_CHECK(xmm0_out[3] == 64.0f);

    OK(uc_close(uc));
}

/* Test VFMADD231PS ymm (256-bit FMA):
 * ymm0 = ymm1 * ymm2 + ymm0
 * ymm0={1,...,1}, ymm1={1,2,...,8}, ymm2={10,...,10}
 * Result = {11,21,31,41,51,61,71,81}
 */
static void test_x86_fma_vfmadd231ps_ymm(void)
{
    uc_engine *uc;

    /*
     * vfmadd231ps ymm0, ymm1, ymm2
     * VEX.256.66.0F38.W0 B8 /r
     * C4 E2 75 B8 C2
     */
    char code[] = { '\xC4', '\xE2', '\x75', '\xB8', '\xC2' };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    float ymm0_in[8] = { 1,1,1,1,1,1,1,1 };
    float ymm1_in[8] = { 1,2,3,4,5,6,7,8 };
    float ymm2_in[8] = { 10,10,10,10,10,10,10,10 };
    OK(uc_reg_write(uc, UC_X86_REG_YMM0, ymm0_in));
    OK(uc_reg_write(uc, UC_X86_REG_YMM1, ymm1_in));
    OK(uc_reg_write(uc, UC_X86_REG_YMM2, ymm2_in));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    float ymm0_out[8];
    OK(uc_reg_read(uc, UC_X86_REG_YMM0, ymm0_out));
    TEST_CHECK(ymm0_out[0] == 11.0f);
    TEST_CHECK(ymm0_out[1] == 21.0f);
    TEST_CHECK(ymm0_out[2] == 31.0f);
    TEST_CHECK(ymm0_out[3] == 41.0f);
    TEST_CHECK(ymm0_out[4] == 51.0f);
    TEST_CHECK(ymm0_out[5] == 61.0f);
    TEST_CHECK(ymm0_out[6] == 71.0f);
    TEST_CHECK(ymm0_out[7] == 81.0f);

    OK(uc_close(uc));
}

/* Test VFMADDSUB231PS xmm0, xmm1, xmm2:
 * Even elements: sub (negate_c), odd elements: add
 * result[0] = xmm1[0]*xmm2[0] - xmm0[0]
 * result[1] = xmm1[1]*xmm2[1] + xmm0[1]
 * result[2] = xmm1[2]*xmm2[2] - xmm0[2]
 * result[3] = xmm1[3]*xmm2[3] + xmm0[3]
 * xmm0={1,1,1,1}, xmm1={2,3,4,5}, xmm2={10,10,10,10}
 * = {20-1, 30+1, 40-1, 50+1} = {19, 31, 39, 51}
 */
static void test_x86_fma_vfmaddsub231ps(void)
{
    uc_engine *uc;

    /*
     * vfmaddsub231ps xmm0, xmm1, xmm2
     * VEX.128.66.0F38.W0 B6 /r
     * C4 E2 71 B6 C2
     */
    char code[] = { '\xC4', '\xE2', '\x71', '\xB6', '\xC2' };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    float xmm0_in[4] = { 1.0f, 1.0f, 1.0f, 1.0f };
    float xmm1_in[4] = { 2.0f, 3.0f, 4.0f, 5.0f };
    float xmm2_in[4] = { 10.0f, 10.0f, 10.0f, 10.0f };
    OK(uc_reg_write(uc, UC_X86_REG_XMM0, xmm0_in));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, xmm1_in));
    OK(uc_reg_write(uc, UC_X86_REG_XMM2, xmm2_in));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    float xmm0_out[4];
    OK(uc_reg_read(uc, UC_X86_REG_XMM0, xmm0_out));
    /* VFMADDSUB: even=sub, odd=add */
    TEST_CHECK(xmm0_out[0] == 19.0f);   /* 2*10 - 1 */
    TEST_CHECK(xmm0_out[1] == 31.0f);   /* 3*10 + 1 */
    TEST_CHECK(xmm0_out[2] == 39.0f);   /* 4*10 - 1 */
    TEST_CHECK(xmm0_out[3] == 51.0f);   /* 5*10 + 1 */

    OK(uc_close(uc));
}

/* Test VFMADD132SS xmm0, xmm1, xmm2 (scalar single 132 form):
 * xmm0[0] = xmm0[0] * xmm2[0] + xmm1[0], upper elements unchanged
 * xmm0={2.0, 99, 99, 99}, xmm1={100, 88, 88, 88}, xmm2={5, 77, 77, 77}
 * Result[0] = 2*5+100 = 110, rest from xmm0 = {99,99,99}
 */
static void test_x86_fma_vfmadd132ss(void)
{
    uc_engine *uc;

    /*
     * vfmadd132ss xmm0, xmm1, xmm2
     * VEX.LIG.66.0F38.W0 99 /r
     * C4 E2 71 99 C2
     */
    char code[] = { '\xC4', '\xE2', '\x71', '\x99', '\xC2' };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    float xmm0_in[4] = { 2.0f, 99.0f, 99.0f, 99.0f };
    float xmm1_in[4] = { 100.0f, 88.0f, 88.0f, 88.0f };
    float xmm2_in[4] = { 5.0f, 77.0f, 77.0f, 77.0f };
    OK(uc_reg_write(uc, UC_X86_REG_XMM0, xmm0_in));
    OK(uc_reg_write(uc, UC_X86_REG_XMM1, xmm1_in));
    OK(uc_reg_write(uc, UC_X86_REG_XMM2, xmm2_in));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    float xmm0_out[4];
    OK(uc_reg_read(uc, UC_X86_REG_XMM0, xmm0_out));
    /* 132 scalar: xmm0[0] = xmm0[0] * xmm2[0] + xmm1[0] = 2*5+100 = 110 */
    TEST_CHECK(xmm0_out[0] == 110.0f);

    OK(uc_close(uc));
}

/* Test VCVTPS2PH + VCVTPH2PS YMM round-trip */
static void test_x86_f16c_ymm(void)
{
    uc_engine *uc;

    /*
     * vcvtps2ph xmm1, ymm0, 0   ; convert 8 floats to 8 half-floats in xmm1
     * VEX.256.66.0F3A.W0 1D /r ib
     * C4 E3 7D 1D C1 00
     *
     * vcvtph2ps ymm2, xmm1       ; convert 8 half-floats back to 8 floats
     * VEX.256.66.0F38.W0 13 /r
     * C4 E2 7D 13 D1
     */
    char code[] = {
        '\xC4', '\xE3', '\x7D', '\x1D', '\xC1', '\x00',  /* vcvtps2ph xmm1, ymm0, 0 */
        '\xC4', '\xE2', '\x7D', '\x13', '\xD1'            /* vcvtph2ps ymm2, xmm1 */
    };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    float ymm0_in[8] = { 1.0f, 2.0f, -0.5f, 65504.0f, 0.0f, -1.0f, 0.25f, 3.0f };
    OK(uc_reg_write(uc, UC_X86_REG_YMM0, ymm0_in));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    float ymm2_out[8];
    OK(uc_reg_read(uc, UC_X86_REG_YMM2, ymm2_out));
    /* Round-trip should preserve these values exactly */
    TEST_CHECK(ymm2_out[0] == 1.0f);
    TEST_CHECK(ymm2_out[1] == 2.0f);
    TEST_CHECK(ymm2_out[2] == -0.5f);
    TEST_CHECK(ymm2_out[3] == 65504.0f);
    TEST_CHECK(ymm2_out[4] == 0.0f);
    TEST_CHECK(ymm2_out[5] == -1.0f);
    TEST_CHECK(ymm2_out[6] == 0.25f);
    TEST_CHECK(ymm2_out[7] == 3.0f);

    OK(uc_close(uc));
}

static void test_x86_avx_vxorps_ymm(void)
{
    uc_engine *uc;
    uint64_t ymm0[4];

    /*
     * Set ymm0 to all-ones, then vxorps ymm0, ymm0, ymm0 should zero it.
     *
     * vxorps ymm0, ymm0, ymm0  ; C5 FC 57 C0
     */
    char code[] = { '\xC5', '\xFC', '\x57', '\xC0' };

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, code, sizeof(code)));

    /* Set ymm0 to all-ones */
    uint64_t all_ones[4] = { 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
                              0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL };
    OK(uc_reg_write(uc, UC_X86_REG_YMM0, &all_ones));

    OK(uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_YMM0, &ymm0));
    TEST_CHECK(ymm0[0] == 0);
    TEST_CHECK(ymm0[1] == 0);
    TEST_CHECK(ymm0[2] == 0);
    TEST_CHECK(ymm0[3] == 0);

    OK(uc_close(uc));
}

static void test_x86_invalid_vex_l(void)
{
    uc_engine *uc;

    /* vmovdqu ymm1, [rcx] */
    char code[] = {'\xC5', '\xFE', '\x6F', '\x09'};

    /* initialize memory and run emulation  */
    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_mem_map(uc, 0, 2 * 1024 * 1024, UC_PROT_ALL));

    OK(uc_mem_write(uc, 0, code, sizeof(code) / sizeof(code[0])));

    /* VEX.L=1 (256-bit) instructions are now supported with AVX */
    OK(uc_emu_start(uc, 0, sizeof(code) / sizeof(code[0]), 0, 0));
    OK(uc_close(uc));
}

// AARCH64 inline the read while s390x won't split the access. Though not tested
// on other hosts but we restrict a bit more.
#if !defined(TARGET_READ_INLINED) && defined(BOOST_LITTLE_ENDIAN)

struct writelog_t {
    uint32_t addr, size;
};

static void test_x86_unaligned_access_callback(uc_engine *uc, uc_mem_type type,
                                               uint64_t address, int size,
                                               int64_t value, void *user_data)
{
    TEST_CHECK(size != 0);
    struct writelog_t *write_log = (struct writelog_t *)user_data;

    for (int i = 0; i < 10; i++) {
        if (write_log[i].size == 0) {
            write_log[i].addr = (uint32_t)address;
            write_log[i].size = (uint32_t)size;
            return;
        }
    }
    TEST_ASSERT(false);
}

static void test_x86_unaligned_access(void)
{
    uc_engine *uc;
    uc_hook hook;
    // mov dword ptr [0x200001], eax; mov eax, dword ptr [0x200001]
    char code[] = "\xa3\x01\x00\x20\x00\xa1\x01\x00\x20\x00";
    uint32_t r_eax = LEINT32(0x41424344);
    struct writelog_t write_log[10];
    struct writelog_t read_log[10];
    memset(write_log, 0, sizeof(write_log));
    memset(read_log, 0, sizeof(read_log));

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);
    OK(uc_mem_map(uc, 0x200000, 0x1000, UC_PROT_ALL));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_WRITE,
                   test_x86_unaligned_access_callback, write_log, 1, 0));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_READ,
                   test_x86_unaligned_access_callback, read_log, 1, 0));

    OK(uc_reg_write(uc, UC_X86_REG_EAX, &r_eax));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    TEST_CHECK(write_log[0].addr == 0x200001);
    TEST_CHECK(write_log[0].size == 4);
    TEST_CHECK(write_log[1].size == 0);

    TEST_CHECK(read_log[0].addr == 0x200001);
    TEST_CHECK(read_log[0].size == 4);
    TEST_CHECK(read_log[1].size == 0);

    char b;
    OK(uc_mem_read(uc, 0x200001, &b, 1));
    TEST_CHECK(b == 0x44);
    OK(uc_mem_read(uc, 0x200002, &b, 1));
    TEST_CHECK(b == 0x43);
    OK(uc_mem_read(uc, 0x200003, &b, 1));
    TEST_CHECK(b == 0x42);
    OK(uc_mem_read(uc, 0x200004, &b, 1));
    TEST_CHECK(b == 0x41);

    OK(uc_close(uc));
}

static void test_x86_64_unaligned_access(void)
{
    uc_engine *uc;
    uc_hook hook;
    char code[] = {"\x48\x89\x01" //   mov         qword ptr [rcx],rax
                   "\x48\x8b\x00" //  mov         rax,qword ptr [rax]
                   "\xcc"};
    uint64_t r_rax = LEINT64(0x2fffff);
    uint64_t r_rcx = LEINT64(0x2fffff);
    struct writelog_t write_log[10];
    struct writelog_t read_log[10];
    memset(write_log, 0, sizeof(write_log));
    memset(read_log, 0, sizeof(read_log));
    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof(code) - 1);
    OK(uc_mem_map(uc, 0x200000, 0x200000, UC_PROT_ALL));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_WRITE,
                   test_x86_unaligned_access_callback, write_log, 1, 0));
    OK(uc_hook_add(uc, &hook, UC_HOOK_MEM_READ,
                   test_x86_unaligned_access_callback, read_log, 1, 0));

    OK(uc_reg_write(uc, UC_X86_REG_RAX, &r_rax));
    OK(uc_reg_write(uc, UC_X86_REG_RCX, &r_rcx));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 2));

    TEST_CHECK(write_log[0].addr == 0x2fffff);
    TEST_CHECK(write_log[0].size == 8);
    TEST_CHECK(write_log[1].size == 0);

    TEST_CHECK(read_log[0].addr == 0x2fffff);
    TEST_CHECK(read_log[0].size == 8);
    TEST_CHECK(read_log[1].size == 0);

    uint64_t b;
    OK(uc_mem_read(uc, 0x2fffff, &b, 8));
    TEST_CHECK(b == 0x2fffff);

    OK(uc_close(uc));
}
#endif

static bool test_x86_lazy_mapping_mem_callback(uc_engine *uc, uc_mem_type type,
                                               uint64_t address, int size,
                                               int64_t value, void *user_data)
{
    OK(uc_mem_map(uc, 0x1000, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0x1000, "\x90\x90", 2)); // nop; nop

    // Handled!
    return true;
}

static void test_x86_lazy_mapping_block_callback(uc_engine *uc,
                                                 uint64_t address,
                                                 uint32_t size, void *user_data)
{
    int *block_count = (int *)user_data;
    (*block_count)++;
}

static void test_x86_lazy_mapping(void)
{
    uc_engine *uc;
    uc_hook mem_hook, block_hook;
    int block_count = 0;

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_hook_add(uc, &mem_hook, UC_HOOK_MEM_FETCH_UNMAPPED,
                   test_x86_lazy_mapping_mem_callback, NULL, 1, 0));
    OK(uc_hook_add(uc, &block_hook, UC_HOOK_BLOCK,
                   test_x86_lazy_mapping_block_callback, &block_count, 1, 0));

    OK(uc_emu_start(uc, 0x1000, 0x1002, 0, 0));
    TEST_CHECK(block_count == 1);
    OK(uc_close(uc));
}

static void test_x86_16_incorrect_ip_cb(uc_engine *uc, uint64_t address,
                                        uint32_t size, void *data)
{
    uint16_t cs, ip;

    OK(uc_reg_read(uc, UC_X86_REG_CS, &cs));
    OK(uc_reg_read(uc, UC_X86_REG_IP, &ip));

    TEST_CHECK(cs == 0x20);
    TEST_CHECK(address == ((cs << 4) + ip));
}

static void test_x86_16_incorrect_ip(void)
{
    uc_engine *uc;
    uc_hook hk1, hk2;
    uint16_t cs = 0x20;
    char code[] = "\x41"; // INC cx;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_16, code, sizeof(code) - 1);

    OK(uc_hook_add(uc, &hk1, UC_HOOK_BLOCK, test_x86_16_incorrect_ip_cb, NULL,
                   1, 0));
    OK(uc_hook_add(uc, &hk2, UC_HOOK_CODE, test_x86_16_incorrect_ip_cb, NULL, 1,
                   0));

    OK(uc_reg_write(uc, UC_X86_REG_CS, &cs));

    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_close(uc));
}

// Porting to BE: Only uc_mem_read/write needs endian fixing
static void test_x86_mmu_prepare_tlb(uc_engine *uc, uint64_t vaddr,
                                     uint64_t tlb_base)
{
    uint64_t cr0;
    uint64_t cr4;
    uc_x86_msr msr = {.rid = 0x0c0000080, .value = 0};
    uint64_t pml4o = ((vaddr & 0x00ff8000000000) >> 39) * 8;
    uint64_t pdpo = ((vaddr & 0x00007fc0000000) >> 30) * 8;
    uint64_t pdo = ((vaddr & 0x0000003fe00000) >> 21) * 8;
    uint64_t pml4e = (tlb_base + 0x1000) | 1 | (1 << 2);
    uint64_t pdpe = (tlb_base + 0x2000) | 1 | (1 << 2);
    uint64_t pde = (tlb_base + 0x3000) | 1 | (1 << 2);
    uint64_t pml4e_mem = LEINT64(pml4e);
    uint64_t pde_mem = LEINT64(pde);
    uint64_t pdpe_mem = LEINT64(pdpe);
    OK(uc_mem_write(uc, tlb_base + pml4o, &pml4e_mem, sizeof(pml4o)));
    OK(uc_mem_write(uc, tlb_base + 0x1000 + pdpo, &pdpe_mem, sizeof(pdpe)));
    OK(uc_mem_write(uc, tlb_base + 0x2000 + pdo, &pde_mem, sizeof(pde)));
    OK(uc_reg_write(uc, UC_X86_REG_CR3, &tlb_base));
    OK(uc_reg_read(uc, UC_X86_REG_CR0, &cr0));
    OK(uc_reg_read(uc, UC_X86_REG_CR4, &cr4));
    OK(uc_reg_read(uc, UC_X86_REG_MSR, &msr));
    cr0 |= 1;
    cr0 |= 1l << 31;
    cr4 |= 1l << 5;
    msr.value |= 1l << 8;
    OK(uc_reg_write(uc, UC_X86_REG_CR0, &cr0));
    OK(uc_reg_write(uc, UC_X86_REG_CR4, &cr4));
    OK(uc_reg_write(uc, UC_X86_REG_MSR, &msr));
}

static void test_x86_mmu_pt_set(uc_engine *uc, uint64_t vaddr, uint64_t paddr,
                                uint64_t tlb_base, bool readwrite)
{
    uint64_t pto = ((vaddr & 0x000000001ff000) >> 12) * 8;
    uint32_t pte;
    if (readwrite)
        pte = (paddr) | 1 | (1 << 2);
    else
        pte = (paddr) | 1;
    pte = LEINT32(pte);

    uc_mem_write(uc, tlb_base + 0x3000 + pto, &pte, sizeof(pte));
}

static void test_x86_mmu_callback(uc_engine *uc, void *userdata)
{
    bool *parrent_done = userdata;
    uint64_t rax;
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &rax));
    switch (rax) {
    case 57:
        /* fork */
        break;
    case 60:
        /* exit */
        uc_emu_stop(uc);
        return;
    default:
        TEST_CHECK(false);
    }

    if (!(*parrent_done)) {
        *parrent_done = true;
        rax = 27;
        OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
        uc_emu_stop(uc);
    }
}

static void test_x86_mmu(void)
{
    bool parrent_done = false;
    uint64_t tlb_base = 0x3000;
    uint64_t parrent, child;
    uint64_t rax, rip;
    uc_context *context;
    uc_engine *uc;
    uc_hook h1;

    /*
     * mov rax, 57
     * syscall
     * test rax, rax
     * jz child
     * xor rax, rax
     * mov rax, 60
     * mov [0x4000], rax
     * syscall
     *
     * child:
     * xor rcx, rcx
     * mov rcx, 42
     * mov [0x4000], rcx
     * mov rax, 60
     * syscall
     */
    char code[] =
        "\xB8\x39\x00\x00\x00\x0F\x05\x48\x85\xC0\x74\x0F\xB8\x3C\x00\x00\x00"
        "\x48\x89\x04\x25\x00\x40\x00\x00\x0F\x05\xB9\x2A\x00\x00\x00\x48\x89"
        "\x0C\x25\x00\x40\x00\x00\xB8\x3C\x00\x00\x00\x0F\x05";

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_ctl_tlb_mode(uc, UC_TLB_CPU));
    OK(uc_hook_add(uc, &h1, UC_HOOK_INSN, &test_x86_mmu_callback, &parrent_done,
                   1, 0, UC_X86_INS_SYSCALL));
    OK(uc_context_alloc(uc, &context));

    OK(uc_mem_map(uc, 0x0, 0x1000, UC_PROT_ALL)); // Code
    OK(uc_mem_write(uc, 0x0, code, sizeof(code) - 1));
    OK(uc_mem_map(uc, 0x1000, 0x1000, UC_PROT_ALL));   // Parrent
    OK(uc_mem_map(uc, 0x2000, 0x1000, UC_PROT_ALL));   // Child
    OK(uc_mem_map(uc, tlb_base, 0x4000, UC_PROT_ALL)); // TLB

    test_x86_mmu_prepare_tlb(uc, 0x0, tlb_base);
    test_x86_mmu_pt_set(uc, 0x2000, 0x0, tlb_base, true);
    test_x86_mmu_pt_set(uc, 0x4000, 0x1000, tlb_base, true);

    OK(uc_ctl_flush_tlb(uc));
    OK(uc_emu_start(uc, 0x2000, 0x0, 0, 0));

    OK(uc_context_save(uc, context));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

    OK(uc_emu_start(uc, rip, 0x0, 0, 0));

    /* restore for child */
    OK(uc_context_restore(uc, context));
    test_x86_mmu_prepare_tlb(uc, 0x0, tlb_base);
    test_x86_mmu_pt_set(uc, 0x4000, 0x2000, tlb_base, true);
    rax = 0;
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    OK(uc_ctl_flush_tlb(uc));

    OK(uc_emu_start(uc, rip, 0x0, 0, 0));
    OK(uc_mem_read(uc, 0x1000, &parrent, sizeof(parrent)));
    OK(uc_mem_read(uc, 0x2000, &child, sizeof(child)));
    TEST_CHECK(LEINT64(parrent) == 60);
    TEST_CHECK(LEINT64(child) == 42);
    OK(uc_context_free(context));
    OK(uc_close(uc));
}

static void test_x86_read_virtual(void)
{
    bool parrent_done = false;
    uint64_t tlb_base = 0x3000;
    uint64_t parrent, child, tmp;
    uint64_t rax, rip;
    uc_context *context;
    uc_engine *uc;
    uc_hook h1;

    /*
     * mov rax, 57
     * syscall
     * test rax, rax
     * jz child
     * xor rax, rax
     * mov rax, 60
     * mov [0x4000], rax
     * syscall
     *
     * child:
     * xor rcx, rcx
     * mov rcx, 42
     * mov [0x4000], rcx
     * mov rax, 60
     * syscall
     */
    char code[] =
        "\xB8\x39\x00\x00\x00\x0F\x05\x48\x85\xC0\x74\x0F\xB8\x3C\x00\x00\x00"
        "\x48\x89\x04\x25\x00\x40\x00\x00\x0F\x05\xB9\x2A\x00\x00\x00\x48\x89"
        "\x0C\x25\x00\x40\x00\x00\xB8\x3C\x00\x00\x00\x0F\x05";

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_ctl_tlb_mode(uc, UC_TLB_CPU));
    OK(uc_hook_add(uc, &h1, UC_HOOK_INSN, &test_x86_mmu_callback, &parrent_done,
                   1, 0, UC_X86_INS_SYSCALL));
    OK(uc_context_alloc(uc, &context));

    OK(uc_mem_map(uc, 0x0, 0x1000, UC_PROT_ALL)); // Code
    OK(uc_mem_write(uc, 0x0, code, sizeof(code) - 1));
    OK(uc_mem_map(uc, 0x1000, 0x1000, UC_PROT_ALL));   // Parrent
    OK(uc_mem_map(uc, 0x2000, 0x1000, UC_PROT_ALL));   // Child
    OK(uc_mem_map(uc, tlb_base, 0x4000, UC_PROT_ALL)); // TLB

    test_x86_mmu_prepare_tlb(uc, 0x0, tlb_base);
    test_x86_mmu_pt_set(uc, 0x2000, 0x0, tlb_base, false);
    test_x86_mmu_pt_set(uc, 0x4000, 0x1000, tlb_base, true);

    OK(uc_ctl_flush_tlb(uc));
    OK(uc_emu_start(uc, 0x2000, 0x0, 0, 0));

    OK(uc_context_save(uc, context));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &rip));

    OK(uc_emu_start(uc, rip, 0x0, 0, 0));
    OK(uc_vmem_read(uc, 0x4000, UC_PROT_READ, &parrent,
                           sizeof(parrent)));

    /* restore for child */
    OK(uc_context_restore(uc, context));
    test_x86_mmu_prepare_tlb(uc, 0x0, tlb_base);
    test_x86_mmu_pt_set(uc, 0x4000, 0x2000, tlb_base, true);
    rax = 0;
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &rax));
    OK(uc_ctl_flush_tlb(uc));

    OK(uc_emu_start(uc, rip, 0x0, 0, 0));
    OK(uc_vmem_read(uc, 0x4000, UC_PROT_READ, &child, sizeof(child)));
    uc_assert_err(
        UC_ERR_READ_PROT,
        uc_vmem_read(uc, 0x1000, UC_PROT_WRITE, &tmp, sizeof(tmp)));
    TEST_CHECK(parrent == 60);
    TEST_CHECK(child == 42);
}

static bool test_x86_vtlb_callback(uc_engine *uc, uint64_t addr,
                                   uc_mem_type type, uc_tlb_entry *result,
                                   void *user_data)
{
    result->paddr = addr;
    result->perms = UC_PROT_ALL;
    return true;
}

static void test_x86_vtlb(void)
{
    uc_engine *uc;
    uc_hook hook;
    char code[] = "\xeb\x02\x90\x90\x90\x90\x90\x90"; // jmp 4; nop; nop; nop;
                                                      // nop; nop; nop
    uint32_t r_eip = 0;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);

    OK(uc_ctl_tlb_mode(uc, UC_TLB_VIRTUAL));
    OK(uc_hook_add(uc, &hook, UC_HOOK_TLB_FILL, test_x86_vtlb_callback, NULL, 1,
                   0));

    OK(uc_emu_start(uc, code_start, code_start + 4, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_EIP, &r_eip));

    TEST_CHECK(r_eip == code_start + 4);

    OK(uc_close(uc));
}

static void test_x86_segmentation(void)
{
    uc_engine *uc;
    uint16_t fs = 0x53;
    uc_x86_mmr gdtr = {0, 0xfffff8076d962000, 0x57, 0};

    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));
    OK(uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr));
    uc_assert_err(UC_ERR_EXCEPTION, uc_reg_write(uc, UC_X86_REG_FS, &fs));
    OK(uc_close(uc));
}

static void test_x86_0xff_lcall_callback(uc_engine *uc, uint64_t address,
                                         uint32_t size, void *user_data)
{
    // do nothing
    return;
}

// This aborts prior to a7a5d187e77f7853755eff4768658daf8095c3b7
static void test_x86_0xff_lcall(void)
{
    uc_engine *uc;
    uc_hook hk;
    const char code[] =
        "\xB8\x01\x00\x00\x00\xBB\x01\x00\x00\x00\xB9\x01\x00\x00\x00\xFF\xDD"
        "\xBA\x01\x00\x00\x00\xB8\x02\x00\x00\x00\xBB\x02\x00\x00\x00";
    // Taken from #1842
    // 0:  b8 01 00 00 00          mov    eax,0x1
    // 5:  bb 01 00 00 00          mov    ebx,0x1
    // a:  b9 01 00 00 00          mov    ecx,0x1
    // f:  ff                      (bad)
    // 10: dd ba 01 00 00 00       fnstsw WORD PTR [edx+0x1]
    // 16: b8 02 00 00 00          mov    eax,0x2
    // 1b: bb 02 00 00 00          mov    ebx,0x2

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);

    OK(uc_hook_add(uc, &hk, UC_HOOK_CODE, test_x86_0xff_lcall_callback, NULL, 1,
                   0));

    uc_assert_err(
        UC_ERR_INSN_INVALID,
        uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_close(uc));
}

static bool test_x86_64_not_overwriting_tmp0_for_pc_update_cb(
    uc_engine *uc, uc_mem_type type, uint64_t address, int size, uint64_t value,
    void *user_data)
{
    return true;
}

// https://github.com/unicorn-engine/unicorn/issues/1717
// https://github.com/unicorn-engine/unicorn/issues/1862
static void test_x86_64_not_overwriting_tmp0_for_pc_update(void)
{
    uc_engine *uc;
    uc_hook hk;
    const char code[] = "\x48\xb9\xff\xff\xff\xff\xff\xff\xff\xff\x48\x89\x0c"
                        "\x24\x48\xd3\x24\x24\x73\x0a";
    uint64_t rsp, pc;
    uint32_t eflags;

    // 0x1000: movabs  rcx, 0xffffffffffffffff
    // 0x100a: mov     qword ptr [rsp], rcx
    // 0x100e: shl     qword ptr [rsp], cl ; (Shift to CF=1)
    // 0x1012: jae     0xd ; this jump should not be taken! (CF=1 but jae
    // expects CF=0)
    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof(code) - 1);
    OK(uc_hook_add(uc, &hk, UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                   test_x86_64_not_overwriting_tmp0_for_pc_update_cb, NULL, 1,
                   0));

    rsp = 0x2000;
    OK(uc_reg_write(uc, UC_X86_REG_RSP, (void *)&rsp));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 4));
    OK(uc_reg_read(uc, UC_X86_REG_RIP, &pc));
    OK(uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags));

    TEST_CHECK(pc == 0x1014);
    TEST_CHECK((eflags & 0x1) == 1);

    OK(uc_close(uc));
}

static void test_fxsave_fpip_x86(void)
{
    // note: fxsave was introduced in Pentium II
    uint8_t code_x86[] = {
        // help testing through NOP offset      [disassembly in at&t syntax]
        0x90, 0x90, 0x90, 0x90, // nop nop nop nop
        // run a floating point instruction
        0xdb, 0xc9, // fcmovne %st(1), %st
        // fxsave needs 512 bytes of storage space
        0x81, 0xec, 0x00, 0x02, 0x00, 0x00, // subl $512, %esp
        // fxsave needs a 16-byte aligned address for storage
        0x83, 0xe4, 0xf0, // andl $0xfffffff0, %esp
        // store fxsave data on the stack
        0x0f, 0xae, 0x04, 0x24, // fxsave (%esp)
        // fxsave stores FPIP at an 8-byte offset, move FPIP to eax register
        0x8b, 0x44, 0x24, 0x08 // movl 0x8(%esp), %eax
    };
    uint32_t X86_NOP_OFFSET = 4;
    uint32_t stack_top = (uint32_t)MEM_STACK;
    uint32_t value;
    uc_engine *uc;

    // initialize emulator in X86-32bit mode
    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));

    // map 1MB of memory for this emulation
    OK(uc_mem_map(uc, MEM_BASE, MEM_SIZE, UC_PROT_ALL));
    OK(uc_mem_write(uc, MEM_TEXT, code_x86, sizeof(code_x86)));
    OK(uc_reg_write(uc, UC_X86_REG_ESP, &stack_top));
    OK(uc_emu_start(uc, MEM_TEXT, MEM_TEXT + sizeof(code_x86), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_EAX, &value));
    TEST_CHECK(value == ((uint32_t)MEM_TEXT + X86_NOP_OFFSET));
    OK(uc_mem_unmap(uc, MEM_BASE, MEM_SIZE));
    OK(uc_close(uc));
}

static void test_fxsave_fpip_x64(void)
{
    uint8_t code_x64[] = {
        // help testing through NOP offset     [disassembly in at&t]
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // nops
        // run a floating point instruction
        0xdb, 0xc9, // fcmovne %st(1), %st
        // fxsave64 needs 512 bytes of storage space
        0x48, 0x81, 0xec, 0x00, 0x02, 0x00, 0x00, // subq $512, %rsp
        // fxsave needs a 16-byte aligned address for storage
        0x48, 0x83, 0xe4, 0xf0, // andq 0xfffffffffffffff0, %rsp
        // store fxsave64 data on the stack
        0x48, 0x0f, 0xae, 0x04, 0x24, // fxsave64 (%rsp)
        // fxsave64 stores FPIP at an 8-byte offset, move FPIP to rax register
        0x48, 0x8b, 0x44, 0x24, 0x08, // movq 0x8(%rsp), %rax
    };

    uint64_t stack_top = (uint64_t)MEM_STACK;
    uint64_t X64_NOP_OFFSET = 8;
    uint64_t value;
    uc_engine *uc;

    // initialize emulator in X86-32bit mode
    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));

    // map 1MB of memory for this emulation
    OK(uc_mem_map(uc, MEM_BASE, MEM_SIZE, UC_PROT_ALL));
    OK(uc_mem_write(uc, MEM_TEXT, code_x64, sizeof(code_x64)));
    OK(uc_reg_write(uc, UC_X86_REG_RSP, &stack_top));
    OK(uc_emu_start(uc, MEM_TEXT, MEM_TEXT + sizeof(code_x64), 0, 0));
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &value));
    TEST_CHECK(value == ((uint64_t)MEM_TEXT + X64_NOP_OFFSET));
    OK(uc_mem_unmap(uc, MEM_BASE, MEM_SIZE));
    OK(uc_close(uc));
}

static void test_bswap_ax(void)
{
    // References:
    // - https://gynvael.coldwind.pl/?id=268
    // - https://github.com/JonathanSalwan/Triton/issues/1131
    {
        uint8_t code[] = {
            // bswap ax
            0x66,
            0x0F,
            0xC8,
        };
        TEST_CODE(UC_MODE_32, code);
        TEST_IN_REG(EAX, 0x44332211);
        TEST_OUT_REG(EAX, 0x44330000);
        TEST_RUN();
    }
    {
        uint8_t code[] = {
            // bswap ax
            0x66,
            0x0F,
            0xC8,
        };
        TEST_CODE(UC_MODE_64, code);
        TEST_IN_REG(RAX, 0x8877665544332211);
        TEST_OUT_REG(RAX, 0x8877665544330000);
        TEST_RUN();
    }
    {
        uint8_t code[] = {
            // bswap rax (66h ignored)
            0x66,
            0x48,
            0x0F,
            0xC8,
        };
        TEST_CODE(UC_MODE_64, code);
        TEST_IN_REG(RAX, 0x8877665544332211);
        TEST_OUT_REG(RAX, 0x1122334455667788);
        TEST_RUN();
    }
    {
        uint8_t code[] = {
            // bswap ax (rex ignored)
            0x48,
            0x66,
            0x0F,
            0xC8,
        };
        TEST_CODE(UC_MODE_64, code);
        TEST_IN_REG(RAX, 0x8877665544332211);
        TEST_OUT_REG(RAX, 0x8877665544330000);
        TEST_RUN();
    }
    {
        uint8_t code[] = {
            // bswap eax
            0x0F,
            0xC8,
        };
        TEST_CODE(UC_MODE_32, code);
        TEST_IN_REG(EAX, 0x44332211);
        TEST_OUT_REG(EAX, 0x11223344);
        TEST_RUN();
    }
    {
        uint8_t code[] = {
            // bswap eax
            0x0F,
            0xC8,
        };
        TEST_CODE(UC_MODE_64, code);
        TEST_IN_REG(RAX, 0x8877665544332211);
        TEST_OUT_REG(RAX, 0x0000000011223344);
        TEST_RUN();
    }
}

static void test_rex_x64(void)
{
    {
        uint8_t code[] = {
            // mov ax, bx (rex.w ignored)
            0x48,
            0x66,
            0x89,
            0xD8,
        };
        TEST_CODE(UC_MODE_64, code);
        TEST_IN_REG(RAX, 0x8877665544332211);
        TEST_IN_REG(RBX, 0x1122334455667788);
        TEST_OUT_REG(RAX, 0x8877665544337788);
        TEST_RUN();
    }
    {
        uint8_t code[] = {
            // mov rax, rbx (66h ignored)
            0x66,
            0x48,
            0x89,
            0xD8,
        };
        TEST_CODE(UC_MODE_64, code);
        TEST_IN_REG(RAX, 0x8877665544332211);
        TEST_IN_REG(RBX, 0x1122334455667788);
        TEST_OUT_REG(RAX, 0x1122334455667788);
        TEST_RUN();
    }
    {
        uint8_t code[] = {
            // mov ax, bx (expected encoding)
            0x66,
            0x89,
            0xD8,
        };
        TEST_CODE(UC_MODE_64, code);
        TEST_IN_REG(RAX, 0x8877665544332211);
        TEST_IN_REG(RBX, 0x1122334455667788);
        TEST_OUT_REG(RAX, 0x8877665544337788);
        TEST_RUN();
    }
}

static bool test_x86_ro_segfault_cb(uc_engine *uc, uc_mem_type type,
                                    uint64_t address, int size, uint64_t value,
                                    void *user_data)
{
    const char code[] = "\xA1\x00\x10\x00\x00\xA1\x00\x10\x00\x00";
    OK(uc_mem_write(uc, address, code, sizeof(code) - 1));
    return true;
}

static void test_x86_ro_segfault(void)
{
    uc_engine *uc;
    // mov eax, [0x1000]
    // mov eax, [0x1000]
    const char code[] = "\xA1\x00\x10\x00\x00\xA1\x00\x10\x00\x00";
    uint32_t out;
    uc_hook hh;

    OK(uc_open(UC_ARCH_X86, UC_MODE_32, &uc));
    OK(uc_mem_map(uc, 0, 0x1000, UC_PROT_ALL));
    OK(uc_mem_write(uc, 0, code, sizeof(code) - 1));
    OK(uc_mem_map(uc, 0x1000, 0x1000, UC_PROT_READ));

    OK(uc_hook_add(uc, &hh, UC_HOOK_MEM_READ, test_x86_ro_segfault_cb, NULL, 1,
                   0));
    OK(uc_emu_start(uc, 0, sizeof(code) - 1, 0, 0));

    OK(uc_reg_read(uc, UC_X86_REG_EAX, (void *)&out));
    TEST_CHECK(out == 0x001000a1);
    OK(uc_close(uc));
}

static bool test_x86_hook_insn_rdtsc_cb(uc_engine *uc, void *user_data)
{
    uint64_t h = 0x00000000FEDCBA98;
    OK(uc_reg_write(uc, UC_X86_REG_RDX, &h));

    uint64_t l = 0x0000000076543210;
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &l));

    return true;
}

static void test_x86_hook_insn_rdtsc(void)
{
    char code[] = "\x0F\x31"; // RDTSC

    uc_engine *uc;
    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof code - 1);

    uc_hook hook;
    OK(uc_hook_add(uc, &hook, UC_HOOK_INSN, test_x86_hook_insn_rdtsc_cb, NULL,
                   1, 0, UC_X86_INS_RDTSC));

    OK(uc_emu_start(uc, code_start, code_start + sizeof code - 1, 0, 0));

    OK(uc_hook_del(uc, hook));

    uint64_t h = 0;
    OK(uc_reg_read(uc, UC_X86_REG_RDX, &h));
    TEST_CHECK(h == 0x00000000FEDCBA98);

    uint64_t l = 0;
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &l));
    TEST_CHECK(l == 0x0000000076543210);

    OK(uc_close(uc));
}

static bool test_x86_hook_insn_rdtscp_cb(uc_engine *uc, void *user_data)
{
    uint64_t h = 0x0000000001234567;
    OK(uc_reg_write(uc, UC_X86_REG_RDX, &h));

    uint64_t l = 0x0000000089ABCDEF;
    OK(uc_reg_write(uc, UC_X86_REG_RAX, &l));

    uint64_t i = 0x00000000DEADBEEF;
    OK(uc_reg_write(uc, UC_X86_REG_RCX, &i));

    return true;
}

static void test_x86_hook_insn_rdtscp(void)
{
    uc_engine *uc;
    OK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc));

    OK(uc_ctl_set_cpu_model(uc, UC_CPU_X86_HASWELL));

    OK(uc_mem_map(uc, code_start, code_len, UC_PROT_ALL));

    char code[] = "\x0F\x01\xF9"; // RDTSCP
    OK(uc_mem_write(uc, code_start, code, sizeof code - 1));

    uc_hook hook;
    OK(uc_hook_add(uc, &hook, UC_HOOK_INSN, test_x86_hook_insn_rdtscp_cb, NULL,
                   1, 0, UC_X86_INS_RDTSCP));

    OK(uc_emu_start(uc, code_start, code_start + sizeof code - 1, 0, 0));

    OK(uc_hook_del(uc, hook));

    uint64_t h = 0;
    OK(uc_reg_read(uc, UC_X86_REG_RDX, &h));
    TEST_CHECK(h == 0x0000000001234567);

    uint64_t l = 0;
    OK(uc_reg_read(uc, UC_X86_REG_RAX, &l));
    TEST_CHECK(l == 0x0000000089ABCDEF);

    uint64_t i = 0;
    OK(uc_reg_read(uc, UC_X86_REG_RCX, &i));
    TEST_CHECK(i == 0x00000000DEADBEEF);

    OK(uc_close(uc));
}

static void test_x86_dr7(void)
{
    uc_engine *uc;
    char code[] =
        "\x48\xC7\xC0\x05\x00\x01\x00\x0F\x23\xF8"; // mov rax, 0x10005
                                                    // mov dr7, rax
    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_64, code, sizeof(code) - 1);
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_close(uc));
}

static void test_x86_hook_block_cb(uc_engine *uc, uint64_t address,
                                   uint32_t size, void *user_data)
{
    uint32_t pc;

    OK(uc_reg_read(uc, UC_X86_REG_EIP, (void *)&pc));

    TEST_CHECK(pc == address);
    *((uint64_t *)user_data) += 1;
}

static void test_x86_hook_block(void)
{
    uc_engine *uc;
    char code[] = "\xeb\x02\x90\x90\x90\x90\x90\x90"; // jmp 4; nop; nop; nop;
                                                      // nop; nop; nop
    uint64_t cnt = 0;
    uc_hook hk;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);

    OK(uc_hook_add(uc, &hk, UC_HOOK_BLOCK, test_x86_hook_block_cb, (void *)&cnt,
                   1, 0));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    TEST_CHECK(cnt == 2);
    OK(uc_close(uc));
}

static bool test_x86_mem_hooks_pc_guarante_mem(uc_engine *uc, uc_mem_type type,
                                               uint64_t addr, int size,
                                               int64_t val, void *data)
{
    if (addr >= code_start + code_len) {
        uint32_t eip;
        OK(uc_reg_read(uc, UC_X86_REG_EIP, (void*)&eip));
        TEST_CHECK(eip == code_start + 1);
    }
    return true;
}

static void test_x86_mem_hooks_pc_guarantee(void)
{
    uc_engine *uc;
    // bs, _ = ks.asm("inc edx; t: mov eax, [ebx]; inc ebx; cmp ebx, ecx; jnz t;")
    char code[] = "\x42\x8b\x03\x43\x39\xcb\x75\xf9";
    uint32_t ebx=code_start + code_len, ecx = code_start + code_len + 0x10;
    uc_hook hk;

    uc_common_setup(&uc, UC_ARCH_X86, UC_MODE_32, code, sizeof(code) - 1);

    OK(uc_mem_map(uc, code_start + code_len, 0x1000, UC_PROT_ALL));
    OK(uc_hook_add(uc, &hk, UC_HOOK_MEM_READ, test_x86_mem_hooks_pc_guarante_mem, NULL,
                   1, 0));
    OK(uc_reg_write(uc, UC_X86_REG_EBX, (void*)&ebx));
    OK(uc_reg_write(uc, UC_X86_REG_ECX, (void*)&ecx));
    OK(uc_emu_start(uc, code_start, code_start + sizeof(code) - 1, 0, 0));

    OK(uc_close(uc));
}

TEST_LIST = {
    {"test_x86_in", test_x86_in},
    {"test_x86_out", test_x86_out},
    {"test_x86_mem_hook_all", test_x86_mem_hook_all},
    {"test_x86_inc_dec_pxor", test_x86_inc_dec_pxor},
    {"test_x86_relative_jump", test_x86_relative_jump},
    {"test_x86_loop", test_x86_loop},
    {"test_x86_invalid_mem_read", test_x86_invalid_mem_read},
    {"test_x86_invalid_mem_write", test_x86_invalid_mem_write},
    {"test_x86_invalid_jump", test_x86_invalid_jump},
    {"test_x86_64_syscall", test_x86_64_syscall},
    {"test_x86_16_add", test_x86_16_add},
    {"test_x86_reg_save", test_x86_reg_save},
    {"test_x86_invalid_mem_read_stop_in_cb",
     test_x86_invalid_mem_read_stop_in_cb},
    {"test_x86_x87_fnstenv", test_x86_x87_fnstenv},
    {"test_x86_mmio", test_x86_mmio},
    {"test_x86_missing_code", test_x86_missing_code},
    {"test_x86_smc_xor", test_x86_smc_xor},
    {"test_x86_smc_add", test_x86_smc_add},
    {"test_x86_smc_mem_hook", test_x86_smc_mem_hook},
    {"test_x86_mmio_uc_mem_rw", test_x86_mmio_uc_mem_rw},
    {"test_x86_sysenter", test_x86_sysenter},
    {"test_x86_hook_cpuid", test_x86_hook_cpuid},
    {"test_x86_486_cpuid", test_x86_486_cpuid},
    {"test_x86_clear_tb_cache", test_x86_clear_tb_cache},
    {"test_x86_clear_empty_tb", test_x86_clear_empty_tb},
    {"test_x86_hook_tcg_op", test_x86_hook_tcg_op},
    {"test_x86_cmpxchg", test_x86_cmpxchg},
    {"test_x86_nested_emu_start", test_x86_nested_emu_start},
    {"test_x86_nested_emu_stop", test_x86_nested_emu_stop},
    {"test_x86_64_nested_emu_start_error", test_x86_64_nested_emu_start_error},
    {"test_x86_eflags_reserved_bit", test_x86_eflags_reserved_bit},
    {"test_x86_nested_uc_emu_start_exits", test_x86_nested_uc_emu_start_exits},
    {"test_x86_clear_count_cache", test_x86_clear_count_cache},
    {"test_x86_correct_address_in_small_jump_hook",
     test_x86_correct_address_in_small_jump_hook},
    {"test_x86_correct_address_in_long_jump_hook",
     test_x86_correct_address_in_long_jump_hook},
    {"test_x86_invalid_vex_l", test_x86_invalid_vex_l},
    {"test_x86_avx_vaddps_ymm", test_x86_avx_vaddps_ymm},
    {"test_x86_avx_vmovdqu_ymm", test_x86_avx_vmovdqu_ymm},
    {"test_x86_avx_vzeroupper", test_x86_avx_vzeroupper},
    {"test_x86_avx_vxorps_ymm", test_x86_avx_vxorps_ymm},
    {"test_x86_avx_vmovdqu_store", test_x86_avx_vmovdqu_store},
    {"test_x86_avx_vbroadcastss", test_x86_avx_vbroadcastss},
    {"test_x86_avx_vperm2f128", test_x86_avx_vperm2f128},
    {"test_x86_avx_vinsertf128", test_x86_avx_vinsertf128},
    {"test_x86_avx_vextractf128", test_x86_avx_vextractf128},
    {"test_x86_avx_vpermilps", test_x86_avx_vpermilps},
    {"test_x86_avx_vpermilpd", test_x86_avx_vpermilpd},
    {"test_x86_avx_vpminsd", test_x86_avx_vpminsd},
    {"test_x86_avx_vtestps", test_x86_avx_vtestps},
    {"test_x86_avx_vtestpd", test_x86_avx_vtestpd},
    {"test_x86_avx_vmaskmovps", test_x86_avx_vmaskmovps},
    {"test_x86_avx_vblendps_ymm", test_x86_avx_vblendps_ymm},
    {"test_x86_avx_vpalignr_ymm", test_x86_avx_vpalignr_ymm},
    {"test_x86_avx_vblendvps", test_x86_avx_vblendvps},
    {"test_x86_avx_vblendvpd", test_x86_avx_vblendvpd},
    {"test_x86_avx_vpblendvb", test_x86_avx_vpblendvb},
    {"test_x86_avx_vpmovsxbw_ymm", test_x86_avx_vpmovsxbw_ymm},
    {"test_x86_avx_vpmovzxbd_ymm", test_x86_avx_vpmovzxbd_ymm},
    {"test_x86_avx2_vpbroadcastd", test_x86_avx2_vpbroadcastd},
    {"test_x86_avx2_vperm2i128", test_x86_avx2_vperm2i128},
    {"test_x86_avx2_vpermd", test_x86_avx2_vpermd},
    {"test_x86_avx2_vpermq", test_x86_avx2_vpermq},
    {"test_x86_avx2_vpsllvd", test_x86_avx2_vpsllvd},
    {"test_x86_avx2_vpacksswb_ymm", test_x86_avx2_vpacksswb_ymm},
    {"test_x86_avx2_vpgatherdd", test_x86_avx2_vpgatherdd},
    {"test_x86_avx_vroundss", test_x86_avx_vroundss},
    {"test_x86_avx2_vpblendd", test_x86_avx2_vpblendd},
    {"test_x86_fma_vfmadd231ps", test_x86_fma_vfmadd231ps},
    {"test_x86_fma_vfnmsub213sd", test_x86_fma_vfnmsub213sd},
    {"test_x86_f16c", test_x86_f16c},
    {"test_x86_avx2_vphaddw_ymm", test_x86_avx2_vphaddw_ymm},
    {"test_x86_fma_vfmadd132ps", test_x86_fma_vfmadd132ps},
    {"test_x86_fma_vfmadd213ps", test_x86_fma_vfmadd213ps},
    {"test_x86_fma_vfmadd231ps_ymm", test_x86_fma_vfmadd231ps_ymm},
    {"test_x86_fma_vfmaddsub231ps", test_x86_fma_vfmaddsub231ps},
    {"test_x86_fma_vfmadd132ss", test_x86_fma_vfmadd132ss},
    {"test_x86_f16c_ymm", test_x86_f16c_ymm},
#if !defined(TARGET_READ_INLINED) && defined(BOOST_LITTLE_ENDIAN)
    {"test_x86_unaligned_access", test_x86_unaligned_access},
    {"test_x86_64_unaligned_access", test_x86_64_unaligned_access},

#endif
    {"test_x86_lazy_mapping", test_x86_lazy_mapping},
    {"test_x86_16_incorrect_ip", test_x86_16_incorrect_ip},
    {"test_x86_mmu", test_x86_mmu},
    {"test_x86_read_virtual", test_x86_read_virtual},
    {"test_x86_vtlb", test_x86_vtlb},
    {"test_x86_segmentation", test_x86_segmentation},
    {"test_x86_0xff_lcall", test_x86_0xff_lcall},
    {"test_x86_64_not_overwriting_tmp0_for_pc_update",
     test_x86_64_not_overwriting_tmp0_for_pc_update},
    {"test_fxsave_fpip_x86", test_fxsave_fpip_x86},
    {"test_fxsave_fpip_x64", test_fxsave_fpip_x64},
    {"test_bswap_x64", test_bswap_ax},
    {"test_rex_x64", test_rex_x64},
    {"test_x86_ro_segfault", test_x86_ro_segfault},
    {"test_x86_hook_insn_rdtsc", test_x86_hook_insn_rdtsc},
    {"test_x86_hook_insn_rdtscp", test_x86_hook_insn_rdtscp},
    {"test_x86_dr7", test_x86_dr7},
    {"test_x86_hook_block", test_x86_hook_block},
    {"test_x86_mem_hooks_pc_guarantee", test_x86_mem_hooks_pc_guarantee},
    {NULL, NULL}};
