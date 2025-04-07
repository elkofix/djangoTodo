% facts:
% parent relationship, binary
parent(pam, bob).
parent(tom, bob).
parent(bob, ann).
parent(bob, pat).
parent(pat, jim).
parent(tom, liz).

abuelo(X, Y) :- parent(X, Z), parent(Z, Y).

padre(X, Y) :- parent(X, Y), male(X).
madre(X, Y) :- parent(X, Y), female(X).

ancestor(X, Y) :- parent(X, Y).
ancestor(X, Y) :- parent(X, Z), ancestor(Z, Y).


% sex relatinoship, unary
female(pam).
female(liz).
female(pat).
female(ann).
male(tom).
male(bob).
male(jim).