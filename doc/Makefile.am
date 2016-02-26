# The following variable is dependent on placement of this file
top_builddir = ..

EXTRA_DIST = \
	pam_hbac.8.txt \
	pam_hbac.conf.5.txt \
	$(NULL)


if HAVE_MANPAGES
### Man pages
SUFFIXES = .5.txt .5 .8.txt .8

EXTRA_DIST += \
	pam_hbac.8 \
	pam_hbac.conf.5 \
	$(NULL)

man_MANS = \
	pam_hbac.8 \
	pam_hbac.conf.5 \
	$(NULL)

.8.txt.8:
	$(A2X) -D $(builddir) --doctype manpage --format manpage $<

.5.txt.5:
	$(A2X) -D $(builddir) --doctype manpage --format manpage $<

clean-local:
	rm -f $(man_MANS)
endif
