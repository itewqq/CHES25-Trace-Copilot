params_asm = dict(
	stack_bottom="0x20000000",
	stack_bottom_free="0x0",
	hardfault_handler_ori="0x0",
	Rx="R9",
    inst_len="0x0",
	new_code="//start of new_code\n",
	pc_relative_translated_code="",
	set_stacked_regs_code = "",
    comp_trans_no_pc="",
    comp_trans_pc="",
    newcode="",
	comp_ncode="",
    comparator_next_pc="",
    next_pc_loader="",
    translated_targets="",
    save_rx="",
    comp_restore_rx="",
    restore_rx="",
    pre_code_asm="",
    post_code_asm="",
    sorted_addr_list="",
    sorted_worker_list="",
    translated_workers="",
    num_workers="",
    reset_handler_ori="",
    reset_hook_code="",
)


# TODO: M0

save_rx_template = '''
'''



template_string_hwb_addr_tracer = '''.syntax unified
.global _start

.text

_start:

// install the hardware breakpoint
new_reset_handler:
	$reset_hook_code
	LDR R0, =$reset_handler_ori //; real Reset_Handler+1
	MOV IP, R0
    BX IP
    .LTORG

new_hard_fault_handler:
    $pre_code_asm
    // get R1 -> stacked context
    TST LR, #4
	ITE EQ
	MRSEQ R1, MSP
	MRSNE R1, PSP
    LDR R0, [R1, #0x18] // original PC, used in post_code_asm, COMMENT this line for trigger
got_PC_location:
    PUSH { LR } // save lr
    // starting search the worker
    shorten_bin_search:
    // r0: target
    // r4: addr[]
    // r2: len
    // return ip=location
    PUSH { R4 }
    LDR R0, [R1, #0x18]         // get PC
    LDR R4, =sorted_addr_list // worker addresses
    LDR R2, =#$num_workers
    mov	ip, #0
	add	r3, r2, ip // r3=(l=0+r)
    asr	r3, r3, #1 // r3 /= 2, mid
.bin_s_loop:
    ldr	lr, [R4, r3, lsl #2] // r3 is mid, lr=addr[mid]
	cmp	lr, r0 // compare arr[mid] with the target
    // ITE GE
	movge	r2, r3 // if greater r=mid
	addlt	ip, r3, #1 // if less than, l=mid+1
	add	r3, r2, ip // r3=l+r
	cmp	r2, ip // if l<r
	asr	r3, r3, #1 // r3= new mid
	bgt	.bin_s_loop // continue
    ldr R4, =sorted_worker_list
    ldr	lr, [R4, ip, lsl #2] // now lr=arr[l]
    POP { R4 }
    bx lr  // jump to the worker
    .LTORG

sorted_addr_list:
    // .word from_address
    $sorted_addr_list

sorted_worker_list:
    // .word worker_address+1
    $sorted_worker_list

translated_workers:
    // worker_0xaafc:
    //      MOV IP, ...
    //      
    $translated_workers

// make sure ip points to the incoming PC
handler_exit:
    LDR R0, [R1, #0x18] // original PC, used in post_code_asm, COMMENT this line for trigger
    STR IP, [R1, #0x18] // write to context->PC
    // return
    POP { LR } // restore exception LR
    // trigger down
    $post_code_asm
    BX LR
'''

logger_reg_formatstr = '''
    // save the cpu context
    PUSH {R4-R11, LR}
    MRS R1, APSR
    PUSH {R1}

    // prepare the prameters
    // R0 still points to oroginal PC
    MOV R2, R0 // the oroginal address
    LDR R1, =0x001C // format string address
    LDR R0, =0x10003 // needed by nrf_log
    // call the logger function
    LDR R3, =0x2CF5 // printer function address, change this manually
    BLX R3

    // restore the cpu context
    POP {R1}
    MSR APSR_nzcvq, R1	
    POP {R4-R11, LR}
'''

logger_reg2string = '''
    // save the cpu context
    PUSH {R4-R11, LR}
    MRS R1, APSR
    PUSH {R1}

    // prepare the prameters
    // R0 still points to oroginal PC
    

    LDR R4, =0x001C // change this manually
PRINT_HEX:
    MOV R1, #8  // number of nibbles (4 bits) in a byte
    MOV R2, #0  // counter for nibbles

LOOP:
    lsl r3, r2, #2  // r3=counter*4
    LSR R3, R0, r3   // shift R0 to isolate each nibble, big endian but we don't care
    AND R3, R3, #0xF  // mask out all but the low nibble
    ADD R3, R3, #'0'  // convert nibble to ASCII character
    CMP R3, #'9'
    BLE DIGIT
    ADD R3, R3, #7  // if A-F, add offset to get correct ASCII value
DIGIT:
    STRB R3, [R4], #1  // store the nibble as a byte in the buffer and increment the buffer pointer
    ADD R2, R2, #1  // increment nibble counter
    CMP R2, R1  // check if all nibbles have been printed
    BLT LOOP  // if not, repeat loop
    
    MOV R3, #0  // put 0x00 byte at the end of the string
    STRB R3, [R4], #1  // store the byte as the last character in the buffer

    LDR R0, =0x10003


    // LDR R1, =0x20040000 // change this manually
    LDR R1, =0x001C
    // call the logger function
    LDR R2, =0x2CE5 //change this manually
    BLX R2



    // restore the cpu context
    POP {R0}
    MSR APSR_nzcvq, R0	
    POP {R4-R11, LR}
'''

template_startend_hooker = '''.syntax unified
.global _start

.text

_start:

// reset handler hooker
new_reset_handler:
	$reset_hook_code
	LDR R0, =$reset_handler_ori //; real Reset_Handler+1
	MOV IP, R0
    BX IP
    .LTORG

new_hard_fault_handler:
    $pre_code_asm
    // get R1 -> stacked context
    TST LR, #4
	ITE EQ
	MRSEQ R1, MSP
	MRSNE R1, PSP
    PUSH { LR } // save lr
    // starting search the worker
    shorten_bin_search:
    // r0: target
    // r4: addr[]
    // r2: len
    // return ip=location
    PUSH { R4 }
    LDR R0, [R1, #0x18]         // get PC
    LDR R4, =sorted_addr_list // worker addresses
    LDR R2, =#$num_workers
    mov	ip, #0
	add	r3, r2, ip // r3=(l=0+r)
    asr	r3, r3, #1 // r3 /= 2, mid
.bin_s_loop:
    ldr	lr, [R4, r3, lsl #2] // r3 is mid, lr=addr[mid]
	cmp	lr, r0 // compare arr[mid] with the target
    // ITE GE
	movge	r2, r3 // if greater r=mid
	addlt	ip, r3, #1 // if less than, l=mid+1
	add	r3, r2, ip // r3=l+r
	cmp	r2, ip // if l<r
	asr	r3, r3, #1 // r3= new mid
	bgt	.bin_s_loop // continue
    ldr R4, =sorted_worker_list
    ldr	lr, [R4, ip, lsl #2] // now lr=arr[l]
    POP { R4 }
    bx lr  // jump to the worker
    .LTORG

sorted_addr_list:
    // .word from_address
    $sorted_addr_list

sorted_worker_list:
    // .word worker_address+1
    $sorted_worker_list

translated_workers:
    // worker_0xaafc:
    //      MOV IP, ...
    //      
    $translated_workers

// make sure ip points to the incoming PC
handler_exit:
    LDR R0, [R1, #0x18] // original PC, used in post_code_asm, COMMENT this line for trigger
    STR IP, [R1, #0x18] // write to context->PC
    // return
    POP { LR } // restore exception LR
    // trigger down
    $post_code_asm
    BX LR
'''

template_string = '''.syntax unified
.global _start

.text

_start:
new_hard_fault_handler:
	// DSB
	// ISB
	TST LR, #4
	ITE EQ
	MRSEQ R1, MSP
	MRSNE R1, PSP
    // dispatch according to ins type
	LDR R0, [R1, #0x18]         // get PC
	LDRB R0, [R0, #1]           // get UDF type
	MOV R2, #0xDE
	CMP R0, R2
    LDR R0, [R1, #0x18]         // get PC
	BEQ short_udf
long_udf:
	LDRB R0, [R0, #2]
	B  dispatch_start
short_udf:
	LDRB R0, [R0, #0]
dispatch_start:
    LSR R2, R0, #4              // get instype: upper 4 bits
	CMP R2, #0x0                // no pc enter
	BEQ no_pc_in
    CMP R2, #0x1
    BEQ no_pc_out
	CMP R2, #0x2                // have pc but no link
	BEQ pc_in
	CMP R2, #0x3
	BEQ pc_out
	CMP R2, #0x4
	BEQ bl_in
	CMP R2, #0x5
	BEQ general_out
default_hard_fault_Handler:
	LDR IP, =$hardfault_handler_ori //; fall back to original hard_fault_Handler
	BX IP

no_pc_in:
    // first save PC to global context
    // note that we shuold note update the global context for new_code_out/ins_pc_relative_out/
    LDR R2, =$stack_bottom
    LDR R0, [R1, #0x18] // R15/orig-PC
    STR R0, [R2, #0x0]          // store the pc to allocated space
    // get next_pc according to orig-PC
    PUSH {R0-R2, LR}
    BL load_next_pc_IP
	POP {R0-R2, LR}
    STR IP, [R2, #0x4] // save next_pc in global context
    // R0 is still orig-PC
    // we should put the target to IP
    // example (no pc):
    // LDR IP, =trans_0x8000
    // CMP R0, 0x8000
    // BEQ no_pc_in_return
    // B label_selector_trans_id
    // LTORG
    // label_selector_trans_id:
    // example (with pc):
    // LDR IP, =trans_0x8000
    // CMP R0, 0x8000
    // BEQ save_rx_label_0x8000
    // B label_selector_trans_id
    // LTORG
    // label_selector_trans_id:
    $comp_trans_no_pc
no_pc_in_return:
    ADD R0, R1, #0x18 // get PC reference
	STR IP, [R0] // set exception context
	BX LR // return to newcode_handlers

no_pc_out:
    // goto new code
new_code_selectors:
    PUSH {R1, R4-R11, LR}  // save context on the stack, and R1
    LDR R2, =$stack_bottom 
    LDR R0, [R2, #0x0]
    // then we can use the PC to indentify the hook function
    // example:
    // LDR R1, =0x8000
    // CMP R0, R1
    // BEQ ncode_0x8000
    // B label_selector_newcode_id
    // LTORG
    // label_selector_newcode_id:
	$comp_ncode

all_newcode:
    $newcode           // each end with B all_newcode_return
all_newcode_return:
	POP {R1, R4-R11, LR}   // restore context from the stack
    // back to normal control flow
general_out:
	// restore the global context to CPU
    LDR R2, =$stack_bottom // dst
    // read next pc in global context
    LDR IP, [R2, #0x4]
	ADD R0, R1, #0x18 //; get PC reference
	STR IP, [R0]

    // set counter=0 in gdb
    // counter++
    LDR R2, =$stack_bottom
    LDR R0, [R2, #0xC] // counter offset
    ADD R0, R0, #1
    STR R0, [R2, #0xC] // write back
    
    // DSB
	// ISB
	BX LR

pc_in:
    // first save PC to global context
    // note that we shuold note update the global context for new_code_out/ins_pc_relative_out/
    LDR R2, =$stack_bottom
    LDR R0, [R1, #0x18] // R15/orig-PC
    STR R0, [R2, #0x0]          // store the pc to allocated space
    // get next_pc according to orig-PC
    PUSH {R0-R2, LR}
    BL load_next_pc_IP
	POP {R0-R2, LR}
    STR IP, [R2, #0x4] // save next_pc in global context
    // R0 is still orig-PC
    // we should put the target to IP
    // example (no pc):
    // LDR IP, =trans_0x8000
    // CMP R0, 0x8000
    // BEQ pc_in_return
    // B label_selector_select_trans_pcin_id
    // LTORG
    // label_selector_select_trans_pcin_id:
    // example (with pc):
    // LDR IP, =trans_0x8000
    // CMP R0, 0x8000
    // BEQ save_rx_label_0x8000
    // B label_selector_select_trans_pcin_id
    // LTORG
    // label_selector_select_trans_pcin_id:
    $comp_trans_pc
    // then we should save the Rx for each target and replace with PC
    // example (not on the stack):
    // save_rx_label_0x00:
    // STR $Rx, [R2, 0x8]
    // LDR $Rx, [R2, 0x0]
    // // ADD $Rx, #$inst_len
    // B pc_in_return
    // LTORG
    // example (on the exception stack):
    // save_rx_label_0x00:
    // LDR R0, [R1, offset]
    // STR R0, [R2, 0x8] // store R0 to Rx-pos
    // LDR R0, [R2, 0x0] // get orig-PC
    // // ADD R0, #$inst_len // shall we add? for b/bl/cbz this does not matter, for tbb/pc-relative/adr we should add 4
    // STR R0, [R1, offset] // write to make it take effect
    // B pc_in_return
    // LTORG
    $save_rx
pc_in_return:
    ADD R0, R1, #0x18 // get PC reference
	STR IP, [R0] // set exception context
	BX LR // return to translated targets
    
pc_out:
	LDR R2, =$stack_bottom 
    B pc_out_start_lp
    .LTORG
    pc_out_start_lp:
    LDR R0, [R2, #0x0]
    // select the restore code
    // example:
    // LDR R3, 0x8000
    // CMP R0, R3
    // BEQ restore_rx_label_0x8000
	$comp_restore_rx
    // restore the rx and write to next PC in global context
    // example (not on the stack):
    // restore_rx_label_0x8000:
    // STR $Rx, [R2, 0x4]
    // LDR $Rx, [R2, 0x8]
    // B no_pc_out
    // example (on the stack):
    // LDR R0, [R1, offset]
    // STR R0, [R2, 0x4]
    // LDR R0, [R2, 0x8]
    // ADD R0, #inst_len?
    // STR R0, [R1, offset]
    // B no_pc_out
	$restore_rx

     
bl_in:
	// first save PC to global context
    // note that we shuold note update the global context for new_code_out/ins_pc_relative_out/
    LDR R2, =$stack_bottom
    B bl_in_start_lp
    .LTORG
    bl_in_start_lp:
    LDR R0, [R1, #0x18] // R15/orig-PC
    STR R0, [R2, #0x0]          // store the pc to allocated space
    // get next_pc according to orig-PC
    PUSH {R0-R2, LR}
    BL load_next_pc_IP
	POP {R0-R2, LR}
    STR IP, [R2, #0x4] // save next_pc in global context
    // R0 is still orig-PC
	ADD R0, R1, #0x14 //; get LR reference
	STR IP, [R0] // write to LR in exception context
    B pc_in
	

// args: R0: PC-value
// returns: IP: next PC-value
// example:
// LDR R1, =target_0x00
// CMP R0, R1
// BEQ next_pc_label_0x00
// next_pc_label_0x00:
// LDR IP, =nextpc_0x00
// BX LR
// .LTORG
load_next_pc_IP:
	$comparator_next_pc
	$next_pc_loader

// load_next_pc_IP_return:
//    BX LR



// Note: Code below will run in thread mode
    .ALIGN 2 // required by ADR instruction
    

translated_targets:
	// all translated targets located here
    // example:
    // trans_0x8000:
    // 		original_code
    //		UDF #0x??
	$translated_targets

'''


template_string_M0 = '''.syntax unified

.text

reset_handler:
	DSB
	ISB
    LDR R0, =$stack_bottom
    MOV SP, R0
    SUB SP, SP, #0x10
	LDR R0, =$reset_handler_ori //; real Reset_Handler+1
	MOV IP, R0
    BX IP

new_hard_fault_handler:
	DSB
	ISB
	MOV R0, LR
	LSRS R0, #3
	BCS is_psp
	MRS R1, MSP
	B checker
is_psp:
	MRS R1, PSP
checker:
	LDR R0, [R1, #0x18]
	LDRB R0, [R0]
	CMP R0, #0xAA
	BEQ ins_no_pc
	CMP R0, #0xAB // have pc but no link
	BEQ ins_pc_relative_in
	CMP R0, #0xAC
	BEQ ins_pc_relative_out
	CMP R0, #0xAD
	BEQ bl_in
	CMP R0, #0xBB
	BEQ run_newcode_go_back
default_hard_fault_Handler:
	LDR R0, =$hardfault_handler_ori //; fall back to original hard_fault_Handler
	MOV IP, R0
	BX IP

ins_no_pc:
	ADR R0, no_pc_handler //; this is the address of no_pc_handler
	MOV R2, R0
	MOV R0, R1
	ADDS R0, R0, #0x18 //; get PC reference
	STR R2, [R0]
	DSB
	ISB
	BX LR

branch_link:_in
	LDR R0, =$pc_next //; this is the address of LR
	MOV R2, R0
	MOV R0, R1
	ADDS R0, R0, #0x14 //; get LR reference
	STR R2, [R0]
	LDR R0, =$stack_bottom_free
	MOV R2, $Rx
	STR R2, [R0] //; backup the original Rx register
	MOV R0, R1
	ADDS R0, R0, #0x18 //; get PC reference
	LDR R2, [R0] //; load original PC to Rx
	MOV $Rx, R2
	$set_stacked_regs_code
	ADR R2, pc_relative_handler //; this is the address of no_pc_handler
	MOV R0, R1
	ADDS R0, R0, #0x18 //; get PC reference
	STR R2, [R0]
	DSB
	ISB
	BX LR

ins_pc_relative_in:
	LDR R0, =$stack_bottom_free
	MOV R2, $Rx
	STR R2, [R0] //; backup the original Rx register
	MOV R0, R1
	ADDS R0, R0, #0x18 //; get PC reference
	LDR R2, [R0] //; load original PC to Rx
	MOV $Rx, R2
	ADDS $Rx, #$inst_len //; add the offset for PC-relative addressing
	$set_stacked_regs_code
	ADR R2, pc_relative_handler //; this is the address of no_pc_handler
	MOV R0, R1
	ADDS R0, R0, #0x18 //; get PC reference
	STR R2, [R0]
	DSB
	ISB
	BX LR

ins_pc_relative_out:
	MOV R0, R1
	ADDS R0, R0, #0x18 //; get PC reference
	MOV R2, $Rx
	STR R2, [R0] //; store the changed PC value
	LDR R0, =$stack_bottom_free
	LDR R2, [R0] //; restore the original Rx register
	MOV $Rx, R2
	$set_stacked_regs_code
	B newcode_start	

run_newcode_go_back:
	LDR R0, =$pc_next //; this is the address of next instruction
	MOV R2, R0
	MOV R0, R1
	ADDS R0, R0, #0x18 //; get PC reference
	STR R2, [R0]
newcode_start:
	$newcode
	// STR R1, [R0,#0x10]
	 //; newcode code end
	DSB
	ISB
	BX LR


// Note: Code below will run in thread mode

    .ALIGN 2 // required by ADR instruction
no_pc_handler:
    $no_pc_inst_ori // we should write the original instruction here
    UDF #0xBB // SVC #0xBB

    .ALIGN 2
pc_relative_handler:
    $pc_relative_translated_code
    UDF #0xAC // goto ins_pc_relative_out

'''

template_string_Exp_Switch_Only = '''.syntax unified

.text

reset_handler:
	DSB
	ISB
	LDR R0, =$reset_handler_ori //; real Reset_Handler+1
	MOV IP, R0
    BX IP

new_hard_fault_handler:
	TST LR, #4
	ITE EQ
	MRSEQ R1, MSP
	MRSNE R1, PSP
	ADD R0, R1, #0x18 //; get PC reference
	LDR IP, =$pc_next
	STR IP, [R0]
	MOV   R1, #0x50000000
	MOV   R3, #0x4000000
	STR   R3, [R1,#0x508]
	BX LR
'''

template_string_Exp_LR_Backup = '''.syntax unified
.global _start

.text

_start:
new_hard_fault_handler:
	DSB
	ISB
	TST LR, #4
	ITE EQ
	MRSEQ R1, MSP
	MRSNE R1, PSP
    // dispatch according to ins type
	LDR R0, [R1, #0x18]         // get PC
	LDRB R0, [R0]               // get imm of UDF instruction
    LSR R2, R0, #4              // get instype: upper 4 bits
	CMP R2, #0x0                // no pc enter
	BEQ no_pc_in
    CMP R2, #0x1
    BEQ no_pc_out
	CMP R2, #0x2                // have pc but no link
	BEQ pc_in
	CMP R2, #0x3
	BEQ pc_out
	CMP R2, #0x4
	BEQ bl_in
	CMP R2, #0x5
	BEQ general_out
default_hard_fault_Handler:
	LDR IP, =$hardfault_handler_ori //; fall back to original hard_fault_Handler
	BX IP

no_pc_in:
    // first save PC to global context
    // note that we shuold note update the global context for new_code_out/ins_pc_relative_out/
    LDR R2, =$stack_bottom
    LDR R0, [R1, #0x18] // R15/orig-PC
    STR R0, [R2, #0x0]          // store the pc to allocated space
    // get next_pc according to orig-PC
    PUSH {R0-R2, LR}
    BL load_next_pc_IP
	POP {R0-R2, LR}
    STR IP, [R2, #0x4] // save next_pc in global context
    // R0 is still orig-PC
    // we should put the target to IP
    // example (no pc):
    // LDR IP, =trans_0x8000
    // CMP R0, 0x8000
    // BEQ no_pc_in_return
    // example (with pc):
    // LDR IP, =trans_0x8000
    // CMP R0, 0x8000
    // BEQ save_rx_label_0x8000
    $comp_trans_no_pc
no_pc_in_return:
    ADD R0, R1, #0x18 // get PC reference
	STR IP, [R0] // set exception context
	BX LR // return to newcode_handlers

no_pc_out:
    // goto new code
new_code_selectors:
    PUSH {R1, R4-R11, LR}  // save context on the stack, and R1
    LDR R2, =$stack_bottom 
    LDR R0, [R2, #0x0]
    // then we can use the PC to indentify the hook function
    // example:
    // LDR R1, =0x8000
    // CMP R0, R1
    // BEQ ncode_0x8000
	$comp_ncode

all_newcode:
    $newcode           // each end with B all_newcode_return
all_newcode_return:
	POP {R1, R4-R11, LR}   // restore context from the stack
    // back to normal control flow
general_out:
	// restore the global context to CPU
    LDR R2, =$stack_bottom // dst
    // read next pc in global context
    LDR IP, [R2, #0x4]
	ADD R0, R1, #0x18 //; get PC reference
	STR IP, [R0]

    DSB
	ISB
	BX LR

pc_in:
    // first save PC to global context
    // note that we shuold note update the global context for new_code_out/ins_pc_relative_out/
    LDR R2, =$stack_bottom
    LDR R0, [R1, #0x18] // R15/orig-PC
    STR R0, [R2, #0x0]          // store the pc to allocated space
    // get next_pc according to orig-PC
    PUSH {R0-R2, LR}
    BL load_next_pc_IP
	POP {R0-R2, LR}
    STR IP, [R2, #0x4] // save next_pc in global context
    // R0 is still orig-PC
    // we should put the target to IP
    // example (no pc):
    // LDR IP, =trans_0x8000
    // CMP R0, 0x8000
    // BEQ pc_in_return
    // example (with pc):
    // LDR IP, =trans_0x8000
    // CMP R0, 0x8000
    // BEQ save_rx_label_0x8000
    $comp_trans_pc
    // then we should save the Rx for each target and replace with PC
    // example (not on the stack):
    // save_rx_label_0x00:
    // STR $Rx, [R2, 0x8]
    // LDR $Rx, [R2, 0x0]
    // ADD $Rx, #$inst_len
    // B pc_in_return
    // example (on the exception stack):
    // save_rx_label_0x00:
    // LDR R0, [R1, offset]
    // STR R0, [R2, 0x8]
    // LDR R0, [R2, 0x0]
    // ADD R0, #$inst_len
    // STR R0, [R1, offset]
    // B pc_in_return
    $save_rx
pc_in_return:
    ADD R0, R1, #0x18 // get PC reference
	STR IP, [R0] // set exception context
	BX LR // return to newcode_handlers
    
pc_out:
	LDR R2, =$stack_bottom 
    LDR R0, [R2, #0x0]
    // select the restore code
    // example:
    // LDR R3, 0x8000
    // CMP R0, R3
    // BEQ restore_rx_label_0x8000
	$comp_restore_rx
    // restore the rx and write to next PC in global context
    // example (not on the stack):
    // restore_rx_label_0x8000:
    // STR $Rx, [R2, 0x4]
    // LDR $Rx, [R2, 0x8]
    // B no_pc_out
    // example (on the stack):
    // LDR R0, [R1, offset]
    // STR R0, [R2, 0x4]
    // LDR R0, [R2, 0x8]
    // STR R0, [R1, offset]
    // B no_pc_out
	$restore_rx	$restore_rx


     
bl_in:
	// first save PC to global context
    // note that we shuold note update the global context for new_code_out/ins_pc_relative_out/
    LDR R2, =$stack_bottom
    LDR R0, [R1, #0x18] // R15/orig-PC
    STR R0, [R2, #0x0]          // store the pc to allocated space
    // get next_pc according to orig-PC
    PUSH {R0-R2, LR}
    BL load_next_pc_IP
	POP {R0-R2, LR}
    STR IP, [R2, #0x4] // save next_pc in global context
    // R0 is still orig-PC
	ADD R0, R1, #0x14 //; get LR reference
	STR IP, [R0] // write to LR in exception context
    B pc_in
	

// args: R0: PC-value
// returns: IP: next PC-value
// example:
// LDR R1, =target_0x00
// CMP R0, R1
// BEQ next_pc_label_0x00
// next_pc_label_0x00:
// LDR IP, =nextpc_0x00
// BX LR
load_next_pc_IP:
	$comparator_next_pc
	$next_pc_loader

// load_next_pc_IP_return:
//    BX LR



// Note: Code below will run in thread mode
    .ALIGN 2 // required by ADR instruction
    

translated_targets:
	// all translated targets located here
    // example:
    // trans_0x8000:
    // 		original_code
    //		UDF #0x??
	$translated_targets

'''