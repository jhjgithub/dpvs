
all clean:
	@cd ..;make $@

custom:
	@echo "Build tags"
	@cd ../../;ctags -R

FMT_SRC=uds.c

format:
	uncrustify --no-backup --mtime -c ../formatter.cfg $(FMT_SRC)
