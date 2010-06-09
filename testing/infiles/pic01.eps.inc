%!PS-Adobe-2.0 EPSF-2.0
%%Title: Unknown
%%Creator: Unknown, using Aspic 1.04 (30-January-2008)
%%CreationDate: Wed, 06 Feb 2008 12:05:35 +0000
%%BoundingBox: 0 0 216.500 72.400
%%EndComments

/centreshow{dup stringwidth pop 2 div neg 0 rmoveto show}def
/rightshow{dup stringwidth pop neg 0 rmoveto show}def
/leftshow{show}def
/mymove{
{currentpoint} stopped {moveto}{
  exch 4 1 roll sub 3 1 roll exch sub
  dup abs 0.01 lt 3 -1 roll dup abs 0.01 lt
  3 -1 roll and {pop pop}{rmoveto} ifelse
  } ifelse
}def
/fonts 64 array def
/mybindfont{exch findfont exch scalefont fonts 3 1 roll put} def
/myfont{fonts exch get setfont} def

0 /Times-Roman 12 mybindfont
0.480 18.360 mymove
72 0 rlineto
0 36 rlineto
-72 0 rlineto
closepath
0.500 setlinewidth
stroke
0 myfont
36.480 33.360 mymove
(A) centreshow
72.480 36.360 mymove
72 0 rlineto
0.400 setlinewidth
stroke
216.480 36.360 mymove
0.480 18.840 -16.080 35.880 -34.920 36 rcurveto
-18.840 1.080 -36.360 -14.880 -37.080 -33.720 rcurveto
-1.680 -18.720 13.800 -36.840 32.520 -38.040 rcurveto
18.720 -2.280 37.200 12.600 39.120 31.320 rcurveto
0.240 1.440 0.240 3 0.240 4.560 rcurveto
closepath
stroke
180.480 33.360 mymove
(B) centreshow
showpage
