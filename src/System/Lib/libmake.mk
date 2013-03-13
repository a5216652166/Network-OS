#Simple rule

$(LIB%_OBJ) : %.o : %.c
	$(CC) -c   -fPIC $(CFLAGS) $< -o $@

#LIB%: $(LIB%_OBJ)
#	$(AR) -crs $SLIB% $(LIB%_OBJ)
clean:
	find . -name *.o | xargs rm -f
	find . -name *.a | xargs rm -f
