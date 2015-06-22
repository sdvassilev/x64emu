; test ops

.code

TestExecShell proc public FRAME
.ENDPROLOG
	add byte ptr[0],al; trigger access violation, so we can setup pre CPU ctx
	
	; from this point on we have to have at least 15 nops to accomodate the
	; longest instruction plust 7 more bytes for another "add byte ptr[0], al"
	; in order to trigger another access violation to capture the post execution
	; cpu context.
	
	nop ;1
	nop ;2
	nop ;3
	nop ;4
	nop ;5
	nop ;6
	nop ;7
	nop ;8
	nop ;9
	nop ;10
	nop ;11
	nop ;12
	nop ;13
	nop ;14
	nop ;15
	
	; add byte ptr[0], al; trigger access violation, so we can setup post CPU ctx
	nop ;1
	nop ;2
	nop ;3
	nop ;4
	nop ;5
	nop ;6
	nop ;7
	ret
TestExecShell endp

end