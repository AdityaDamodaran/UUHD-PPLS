"""
SPDX-FileCopyrightText: 2021 University of Luxembourg
SPDX-License-Identifier: GPL-3.0-or-later
SPDXVersion: SPDX-2.2

Authors: 
       Aditya Damodaran, aditya.damodaran@uni.lu
       Alfredo Rial, alfredo.rial@uni.lu
"""


def dict_from_class(cls):
    excluded_keys = ["__dict__", "__doc__", "__module__", "__weakref__"]
    return dict(
        (key, value)
        for (key, value) in cls.__dict__.items()
        if key not in excluded_keys
    )


class ZKInstance:
    def __init__(self):
        self.bsig = {"Rd": 0, "Sd": 0, "Td": 0}
        self.par = {"g": 0, "h": 0, "par_g": [], "par_h": []}
        self.vcomd = 0
        self.sid = 0
        self.pk = {"Z": 0, "U": [], "W": [], "V": 0}
        self.par_c = {"h": 0, "g": 0}
        self.ins_i = []
        self.bh = 0
        self.bht = 0
        self.comd = 0

    def set_bsig(self, R, S, T):
        self.bsig["Rd"], self.bsig["Sd"], self.bsig["Td"] = R, S, T

    def set_bh(self, bh):
        self.bh = bh

    def set_par(self, par):
        self.par["g"], self.par["h"], self.par["par_g"], self.par["par_h"] = (
            par["g"],
            par["h"],
            par["par_g"],
            par["par_h"],
        )

    def set_vcomd(self, vcomd):
        self.vcomd = vcomd

    def set_sid(self, sid):
        self.sid = sid

    def set_pk(self, pk):
        self.pk["Z"], self.pk["U"], self.pk["W"], self.pk["V"] = (
            pk["Z"],
            pk["U"],
            pk["W"],
            pk["V"],
        )

    def set_par_c(self, par_c):
        self.par_c["h"], self.par_c["g"] = par_c["h"], par_c["g"]

    def append_subinstances(self, ins):
        self.ins_i.append(dict_from_class(ins))

    def set_bht(self, bht):
        self.bht = bht

    def set_comd(self, comd):
        self.comd = comd


class SubInstanceRecord:
    def __init__(
        self, index=0, ccom_i=0, ccom_ri=0, sig=None, phd_i=0, witd_i=0
    ):
        self.sig = {"R_id": 0, "S_id": 0, "T_id": 0}
        self.index, self.ccom_i, self.ccom_ri, self.phd_i, self.witd_i = (
            0,
            0,
            0,
            0,
            0,
        )
        self.set_ccom(index, ccom_i, ccom_ri)
        self.set_sig(sig)
        self.set_phd_i(phd_i)
        self.set_witd_i(witd_i)

    def set_ccom(self, index, ccom_i, ccom_ri):
        self.index = index
        self.ccom_i = ccom_i
        self.ccom_ri = ccom_ri

    def set_sig(self, sig):
        self.sig["R_id"], self.sig["S_id"], self.sig["T_id"] = (
            sig["R_id"],
            sig["S_id"],
            sig["T_id"],
        )

    def set_phd_i(self, phd_i):
        self.phd_i = phd_i

    def set_witd_i(self, witd_i):
        self.witd_i = witd_i


class ZKWitness:
    def __init__(self):
        self.d1 = 0
        self.d2 = 0
        self.d3 = 0
        self.d4 = 0
        self.d5 = 0
        self.wit_i = []

    def set_d(self, d1, d2, d3, d4, d5):
        self.d1, self.d2, self.d3, self.d4, self.d5 = d1, d2, d3, d4, d5

    def append_subwitnesses(self, subwitnesses):
        self.wit_i.append(dict_from_class(subwitnesses))


class SubWitnessRecord:
    def __init__(
        self,
        index=0,
        i=0,
        vr=0,
        copen_i=0,
        copen_ri=0,
        d1=0,
        d2=0,
        d3=0,
        d4=0,
        d5=0,
    ):
        self.set_ivr(index, i, vr)
        self.set_copen(copen_i, copen_ri)
        self.set_d(d1, d2, d3, d4, d5)

    def set_ivr(self, index, i, vr):
        self.index, self.i, self.vr = index, i, vr

    def set_copen(self, copen_i, copen_ri):
        self.copen_i, self.copen_ri = copen_i, copen_ri

    def set_d(self, d1, d2, d3, d4, d5):
        self.di_1, self.di_2, self.di_3, self.di_4, self.di_5 = (
            d1,
            d2,
            d3,
            d4,
            d5,
        )
