'''
SPDX-FileCopyrightText: 2021 University of Luxembourg
SPDX-License-Identifier: GPL-3.0-or-later
SPDXVersion: SPDX-2.2
Authors: 
       Aditya Damodaran, aditya.damodaran@uni.lu
       Alfredo Rial, alfredo.rial@uni.lu
'''

import weakref

from charm.toolbox.pairinggroup import ZR, G1, G2, pair
from charm.toolbox.integergroup import RSAGroup
from charm.core.math.integer import integer

from uuhd.sigmaprotocol import SigmaProtocol, get_record_by_index
from uuhd.jsonobjects import dict_from_class
from uuhd.primitives import PaillierEncryption, SHA256, DSA, IntegerCommitment


class WeakReference:
    _id2obj_dict = weakref.WeakValueDictionary()

    def __init__(self):
        pass

    def remember(self, obj):
        oid = id(obj)
        self._id2obj_dict[oid] = obj
        return oid

    def id2obj(self, oid):
        return self._id2obj_dict[oid]


class FNYM:
    txn = []

    def __init__(self, weak_reference):
        self.weak_reference = weak_reference

    def insert(self, sid, pseudonym, from_id):
        self.txn.append({"sid": sid, "P": pseudonym, "Tk": from_id})

    def send(self, sid, message, pseudonym, from_id, to_id):
        self.txn.append({"sid": sid, "P": pseudonym, "Tk": from_id})
        self.weak_reference.id2obj(to_id).message_in(message, pseudonym)

    def reply(self, message, pseudonym):
        for txnitem in self.txn:
            if txnitem["P"] == pseudonym:
                self.weak_reference.id2obj(txnitem["Tk"]).message_in(
                    message, pseudonym
                )
                del txnitem
                return
        print("Abort: (FNYM) Sender not found.")
        exit(0)


class FZK:
    txn = []

    def __init__(self, fnym, keylength):
        self.fnym = fnym
        self.keylength = keylength

    def prove(self, sid, witness, instance, pseudonym, from_id, to_id):
        # witness mapping:
        # 1=d1  #2=d2  #3=d3  #4=d4  #5=d5
        # 6.1=i #6.2= open_i  #6.3=vr #6.4= open_ri
        # 6.5=di_1 #6.6=di_2  #6.7=di_3 #6.8=di_4
        # 6.9=di_5

        # Load sigs
        Rd, Sd, Td = (
            instance["bsig"]["Rd"],
            instance["bsig"]["Sd"],
            instance["bsig"]["Td"],
        )

        public_key = instance["pk"]
        V, Z = public_key["V"], public_key["Z"]
        W1, W2 = public_key["W"][1], public_key["W"][2]
        U1 = public_key["U"][1]

        h, ht = instance["bh"], instance["bht"]

        d1, d2, d3, d4, d5 = (
            witness["d1"],
            witness["d2"],
            witness["d3"],
            witness["d4"],
            witness["d5"],
        )

        g, gt = instance["par"]["g"], instance["par"]["h"]
        ped_g, ped_h = instance["par_c"]["g"], instance["par_c"]["h"]

        vcomd, comd = instance["vcomd"], instance["comd"]

        subinstance_list = instance["ins_i"]
        subwitnesss_list = witness["wit_i"]

        sigma_protocol = SigmaProtocol(instance, "BN256", self.keylength)

        y1 = sigma_protocol.compute_ppe_1(d1, d2, d3, d4, "lhs")
        y2 = sigma_protocol.compute_ppe_2(d1, d5, "lhs")

        index = 0
        y_list = []

        for subinstance_record in subinstance_list:
            subwitness_record = get_record_by_index(
                subinstance_record["index"], subwitnesss_list
            )
            y3 = sigma_protocol.compute_ppe_3(
                subinstance_record["index"],
                subwitness_record["i"],
                subwitness_record["copen_i"],
                "lhs",
            )
            y4 = sigma_protocol.compute_ppe_4(
                subinstance_record["index"],
                subwitness_record["vr"],
                subwitness_record["copen_ri"],
                "lhs",
            )
            y5 = sigma_protocol.compute_ppe_5(
                subinstance_record["index"],
                subwitness_record["di_1"],
                subwitness_record["di_2"],
                subwitness_record["i"],
                "lhs",
            )
            y6 = sigma_protocol.compute_ppe_6(
                subinstance_record["index"],
                subwitness_record["di_1"],
                subwitness_record["di_3"],
                subwitness_record["di_4"],
                "lhs",
            )
            y7 = sigma_protocol.compute_ppe_7(
                subinstance_record["index"],
                subwitness_record["di_4"],
                subwitness_record["di_5"],
                subwitness_record["vr"],
                "lhs",
            )
            y_list.append(
                {
                    "index": index,
                    "y3": y3,
                    "y4": y4,
                    "y5": y5,
                    "y6": y6,
                    "y7": y7,
                }
            )
            index = index + 1
        y = {"y1": y1, "y2": y2, "yl": y_list}

        random_witness = sigma_protocol.prepare_random_witnesses(witness)

        witness_ic, witness_ico = sigma_protocol.prepare_integer_commitments(
            witness
        )

        witness_pe = sigma_protocol.prepare_paillier_ciphertexts(witness)

        (
            random_ic,
            random_ico,
        ) = sigma_protocol.prepare_random_integer_commitments(
            dict_from_class(random_witness)
        )

        random_pe = sigma_protocol.prepare_random_paillier_ciphertexts(
            dict_from_class(random_witness)
        )
        c = sigma_protocol.verifier_step_1()
        t = {
            "tj": sigma_protocol.compute_t(dict_from_class(random_witness)),
            "tcj": random_ic,
            "wcj": witness_ic,
        }

        hash_y = SHA256(
            (str(y) + str(dict_from_class(witness_ic)) + str(t)).encode(
                "utf-8"
            )
        )

        dsa_a = sigma_protocol.dsa.generate_random()
        dsa_b = sigma_protocol.dsa.generate_random()
        gd = sigma_protocol.dsa_keys[0]["g"] ** dsa_a
        tag = (
            sigma_protocol.dsa_keys[0]["g"]
            ** integer(SHA256(str(sid).encode("utf-8")))
        ) * (sigma_protocol.dsa_keys[0]["y"] ** gd)
        dsa_c = (gd ** dsa_b) * (tag ** integer(hash_y))

        r = {
            "rj": random_witness,
            "rco": random_ic,
            "wco": witness_ic,
        }

        s_j, hashes_j, hash_c = sigma_protocol.prover_step_2(
            dict_from_class(random_witness),
            c,
            witness,
            dict_from_class(random_ico),
            dict_from_class(witness_ico),
        )
        sigma_protocol.verifier_step_2(
            s_j, t, c, y, gd, dsa_c, dsa_b, witness_ic, sid
        )

        if (
            sigma_protocol.verify_integer_commitments(
                hash_c,
                dict_from_class(random_ico),
                dict_from_class(witness_ico),
                dict_from_class(random_ic),
                dict_from_class(witness_ic),
                dict_from_class(hashes_j),
                sigma_protocol.par_ic,
            )
            == 1
        ):

            if (
                sigma_protocol.verify_paillier_ciphertexts(
                    hash_c,
                    dict_from_class(random_pe),
                    dict_from_class(witness_pe),
                    dict_from_class(hashes_j),
                )
                != 1
            ):
                print("Abort: (FZK) Paillier ciphertext verification failed.")
                exit(0)
            self.fnym.insert(sid, pseudonym, from_id)
            self.txn.append({"sid": sid, "P": pseudonym, "Tk": from_id})
            self.fnym.weak_reference.id2obj(to_id).proof_in(
                instance, pseudonym
            )
        else:
            print("Abort: (FZK) Integer commitment verification failed.")
            exit(0)


class FZK_RD:
    l_store = []

    def __init__(self, f_nym, keylength):
        self.f_nym = f_nym
        self.keylength = keylength

    def sign_u(self, i, g, x):
        return g ** ((x + i) ** -1)

    def num_to_str(self, num, length):
        str_num = str(num)
        if len(str_num) < length:
            str_num = "0" * (length - len(str_num)) + str_num
        return str_num

    def prove(self, sid, witness_rd, instance_rd, id, par_c, group):

        [v_n, open_v_n] = witness_rd["Vn"], witness_rd["openVn"]
        [points, com_v_n, com_db_size, db_size, open_db_size] = (
            instance_rd["points"],
            instance_rd["comVn"],
            instance_rd["comN"],
            instance_rd["N"],
            instance_rd["openN"],
        )

        ped_g = par_c["g"]
        ped_h = par_c["h"]

        rsa_group = RSAGroup()
        self.paillier_encryption = PaillierEncryption(rsa_group)

        (self.public_key, self.secret_key) = self.paillier_encryption.keygen(
            self.keylength
        )

        # Verifier picks x rand
        x = group.random(ZR)
        y = ped_h ** x

        u_list = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

        a_i = [
            self.sign_u(0, ped_g, x),
            self.sign_u(1, ped_g, x),
            self.sign_u(2, ped_g, x),
            self.sign_u(3, ped_g, x),
            self.sign_u(4, ped_g, x),
            self.sign_u(5, ped_g, x),
            self.sign_u(6, ped_g, x),
            self.sign_u(7, ped_g, x),
            self.sign_u(8, ped_g, x),
            self.sign_u(9, ped_g, x),
        ]

        str_num = self.num_to_str(v_n - points, 4)

        v_0 = group.random(ZR)
        v_1 = group.random(ZR)
        v_2 = group.random(ZR)
        v_3 = group.random(ZR)

        v_j = [
            a_i[int(str_num[3])] ** v_0,
            a_i[int(str_num[2])] ** v_1,
            a_i[int(str_num[1])] ** v_2,
            a_i[int(str_num[0])] ** v_3,
        ]

        s_0 = group.random(ZR)
        t_0 = group.random(ZR)
        m_0 = group.random(ZR)

        s_1 = group.random(ZR)
        t_1 = group.random(ZR)
        m_1 = group.random(ZR)

        s_2 = group.random(ZR)
        t_2 = group.random(ZR)
        m_2 = group.random(ZR)

        s_3 = group.random(ZR)
        t_3 = group.random(ZR)
        m_3 = group.random(ZR)

        gt = group.random(G2)

        a_0 = (pair(v_j[0], gt) ** (-s_0)) * (pair(ped_g, gt) ** t_0)
        a_1 = (pair(v_j[1], gt) ** (-s_1)) * (pair(ped_g, gt) ** t_1)
        a_2 = (pair(v_j[2], gt) ** (-s_2)) * (pair(ped_g, gt) ** t_2)
        a_3 = (pair(v_j[3], gt) ** (-s_3)) * (pair(ped_g, gt) ** t_3)

        d = (
            ((ped_g ** ((10 ** 0) * s_0)) * (ped_h ** m_0))
            * ((ped_g ** ((10 ** 1) * s_1)) * (ped_h ** m_1))
            * ((ped_g ** ((10 ** 2) * s_2)) * (ped_h ** m_2))
            * ((ped_g ** ((10 ** 3) * s_3)) * (ped_h ** m_3))
        )

        # Verifier
        c = group.random(ZR)

        # Prover
        z_s_0 = s_0 - (int(str_num[3]) * c)
        z_v_0 = t_0 - (v_0 * c)
        z_r_0 = m_0 - (open_v_n * c)
        z_s_1 = s_1 - (int(str_num[2]) * c)
        z_v_1 = t_1 - (v_1 * c)
        z_r_1 = m_1 - (open_v_n * c)
        z_s_2 = s_2 - (int(str_num[1]) * c)
        z_v_2 = t_2 - (v_2 * c)
        z_r_2 = m_2 - (open_v_n * c)
        z_s_3 = s_3 - (int(str_num[0]) * c)
        z_v_3 = t_3 - (v_3 * c)
        z_r_3 = m_3 - (open_v_n * c)
        y_2 = gt ** x
        z_r = (m_0 + m_1 + m_2 + m_3) - (open_v_n * c)
        if not (
            a_0
            == (pair(v_j[0], y_2) ** c)
            * (pair(v_j[0], gt) ** -z_s_0)
            * (pair(ped_g, gt) ** z_v_0)
        ):
            print("Abort: (FZK_RD) A0 check failed.")
        if not (
            a_1
            == (pair(v_j[1], y_2) ** c)
            * (pair(v_j[1], gt) ** -z_s_1)
            * (pair(ped_g, gt) ** z_v_1)
        ):
            print("Abort: (FZK_RD) A1 check failed.")
        if not (
            a_2
            == (pair(v_j[2], y_2) ** c)
            * (pair(v_j[2], gt) ** -z_s_2)
            * (pair(ped_g, gt) ** z_v_2)
        ):
            print("Abort: (FZK_RD) A2 check failed.")
        if not (
            a_3
            == (pair(v_j[3], y_2) ** c)
            * (pair(v_j[3], gt) ** -z_s_3)
            * (pair(ped_g, gt) ** z_v_3)
        ):
            print("Abort: (FZK_RD) A3 check failed.")
        if not (
            d
            == (com_v_n ** c)
            * (~(ped_g ** (points * c)))
            * (ped_h ** (z_r))
            * ((ped_g ** ((10 ** 0) * z_s_0)))
            * ((ped_g ** ((10 ** 1) * z_s_1)))
            * ((ped_g ** ((10 ** 2) * z_s_2)))
            * ((ped_g ** ((10 ** 3) * z_s_3)))
        ):
            print("Abort: (FZK_RD) D check failed.")
        v_n_c = self.paillier_encryption.encrypt(
            self.public_key, integer(((v_n)))
        )
        open_db_size_c = self.paillier_encryption.encrypt(
            self.public_key, integer(SHA256(bytes(str(open_db_size), "utf-8")))
        )

        r_c_1 = group.random(ZR)
        r_c_2 = group.random(ZR)

        ciphertext_r_c_1 = self.paillier_encryption.encrypt(
            self.public_key, integer(SHA256(bytes(str(r_c_1), "utf-8")))
        )
        ciphertext_r_c_2 = self.paillier_encryption.encrypt(
            self.public_key, integer(SHA256(bytes(str(r_c_2), "utf-8")))
        )

        paillier_g, paillier_n, paillier_n_2 = (
            self.public_key["g"],
            self.public_key["n"],
            self.public_key["n2"],
        )

        hash_c = integer(SHA256(bytes(str(c), "utf-8")))
        c_1 = {"c": ciphertext_r_c_1[0]["c"] * (v_n_c[0]["c"] ** hash_c)}
        c_2 = {
            "c": ciphertext_r_c_2[0]["c"] * (open_db_size_c[0]["c"] ** hash_c)
        }
        if not (
            (c_1["c"] % paillier_n_2)
            == (
                (
                    (
                        (paillier_g % paillier_n_2)
                        ** (
                            integer(SHA256(bytes(str(r_c_1), "utf-8")))
                            + (hash_c * integer(v_n))
                        )
                    )
                    * (
                        (
                            ciphertext_r_c_1[1]
                            * (v_n_c[1] ** hash_c)
                            % paillier_n_2
                        )
                        ** paillier_n
                    )
                )
                % paillier_n_2
            )
        ):
            print("Abort: (FZK_RD) Paillier ciphertext verification failed.")
        if not (
            (c_2["c"] % paillier_n_2)
            == (
                (
                    (
                        (paillier_g % paillier_n_2)
                        ** (
                            integer(SHA256(bytes(str(r_c_2), "utf-8")))
                            + (
                                hash_c
                                * integer(
                                    SHA256(bytes(str(open_db_size), "utf-8"))
                                )
                            )
                        )
                    )
                    * (
                        (
                            ciphertext_r_c_2[1]
                            * (open_db_size_c[1] ** hash_c)
                            % paillier_n_2
                        )
                        ** paillier_n
                    )
                )
                % paillier_n_2
            )
        ):
            print("Abort: (FZK_RD) Paillier ciphertext verification failed.")
            exit()
        dsa_p = integer(
            156053402631691285300957066846581395905893621007563090607988086498527791650834395958624527746916581251903190331297268907675919283232442999706619659475326192111220545726433895802392432934926242553363253333261282122117343404703514696108330984423475697798156574052962658373571332699002716083130212467463571362679
        )

        dsa_q = integer(
            78026701315845642650478533423290697952946810503781545303994043249263895825417197979312263873458290625951595165648634453837959641616221499853309829737663096055610272863216947901196216467463121276681626666630641061058671702351757348054165492211737848899078287026481329186785666349501358041565106233731785681339
        )

        dsa = DSA(dsa_p, dsa_q)

        dsa_keys = dsa.generate_keys(self.keylength)
        hash_y = SHA256(str(y_2).encode("utf-8"))
        dsa_a = dsa.generate_random()
        dsa_b = dsa.generate_random()
        g_d = dsa_keys[0]["g"] ** dsa_a
        tag = (
            dsa_keys[0]["g"] ** integer(SHA256(str(sid).encode("utf-8")))
        ) * (dsa_keys[0]["y"] ** g_d)
        dsa_c = (g_d ** dsa_b) * (tag ** integer(hash_y))

        hash_m = SHA256(str(y_2).encode("utf-8"))
        dsa_h = (
            dsa_keys[0]["g"] ** integer(SHA256(str(sid).encode("utf-8")))
        ) * (dsa_keys[0]["y"] ** g_d)
        if not (((g_d ** dsa_b) * (dsa_h ** integer(hash_m))) == (dsa_c)):
            print("Abort: (FZK_RD) DSA check failed.")
            exit()

        self.l_store.append({"sid": sid, "p": id, "Tk": id})
        self.f_nym.insert(sid, id, id)


class FZK_PR3:
    l_store = []

    def __init__(self, f_nym, keylength):
        self.f_nym = f_nym
        self.keylength = keylength

    def get_record_by_index(self, list, index):
        for item in list:
            if item["i"] == index:
                return item

    def sign_u(self, i, g, x):
        return g ** ((x + i) ** -1)

    def num_to_str(self, num, length):
        str_num = str(num)
        if len(str_num) < length:
            str_num = "0" * (length - len(str_num)) + str_num

        return str_num

    def prove(
        self, sid, witness_pr, instance_pr, id, start, end, par_c, group
    ):

        # COM CHECKS
        ped_g = par_c["g"]
        ped_h = par_c["h"]
        g = group.random(G1)
        gt = group.random(G2)
        result = 0
        ppe = 1
        y_list = []
        t_list = []
        integer_commitments = []
        random_witnesses = []
        random_integer_commitments = []
        paillier_ciphertexts = []
        random_paillier_ciphertexts = []
        dsa_p = integer(
            156053402631691285300957066846581395905893621007563090607988086498527791650834395958624527746916581251903190331297268907675919283232442999706619659475326192111220545726433895802392432934926242553363253333261282122117343404703514696108330984423475697798156574052962658373571332699002716083130212467463571362679
        )

        dsa_q = integer(
            78026701315845642650478533423290697952946810503781545303994043249263895825417197979312263873458290625951595165648634453837959641616221499853309829737663096055610272863216947901196216467463121276681626666630641061058671702351757348054165492211737848899078287026481329186785666349501358041565106233731785681339
        )

        ic_p = integer(
            333437049425486136095925931727629203622119239282802038455917646172563395024265917241890473852501318262109839243221497854682815506880304349748481648877420618747530394310060738051284980323398797638078562462943477904211178707988798971266777314022673227003284335883622084916018185539789562312940907090712386355299
        )
        ic_q = integer(
            294092988306368388636535355362351220952777074915662080329740789451817968606482246364359892865057621298389179478994706465098262699509935804409002480293234947971872131356003427444279672200378079370695651721652248116723483318427208508192689675310517884904089979454005634358395042846262967137935407297336359215239
        )

        integer_commitment = IntegerCommitment(ic_p, ic_q, self.keylength)
        par_ic = integer_commitment.setup()
        dsa = DSA(dsa_p, dsa_q)

        dsa_keys = dsa.generate_keys(self.keylength)
        c = group.random(ZR)
        hash_c = integer(SHA256(bytes(str(c), "utf-8")))
        s_ppe = 1

        for instance_record in instance_pr:
            witness_record = self.get_record_by_index(
                witness_pr, instance_record["i"]
            )
            random_v, random_opening_v = group.random(ZR), group.random(ZR)
            y_list.append(
                {
                    "i": witness_record["i"],
                    "e": pair(instance_record["comv"], gt),
                }
            )
            t_list.append(
                {
                    "i": witness_record["i"],
                    "e": (pair(ped_g, gt) ** random_v)
                    * (pair(ped_h, gt) ** random_opening_v),
                }
            )

            result = result + witness_record["v"]
            integer_commitment_v = integer_commitment.commit(
                par_ic, integer(witness_record["v"])
            )
            integer_commitment_open_v = integer_commitment.commit(
                par_ic,
                integer(SHA256(bytes(str(witness_record["openv"]), "utf-8"))),
            )
            integer_commitments.append(
                {
                    "i": witness_record["i"],
                    "iv": integer_commitment_v,
                    "io": integer_commitment_open_v,
                }
            )
            integer_commitment_random_v = integer_commitment.commit(
                par_ic, integer(SHA256(bytes(str(random_v), "utf-8")))
            )
            integer_commitment_random_open_v = integer_commitment.commit(
                par_ic, integer(SHA256(bytes(str(random_opening_v), "utf-8")))
            )
            random_integer_commitments.append(
                {
                    "i": witness_record["i"],
                    "irv": integer_commitment_random_v,
                    "iro": integer_commitment_random_open_v,
                }
            )

            self.paillier_encryption = PaillierEncryption(RSAGroup())

            (
                self.public_key,
                self.secret_key,
            ) = self.paillier_encryption.keygen(self.keylength)
            paillier_g, paillier_n, paillier_n_2 = (
                self.public_key["g"],
                self.public_key["n"],
                self.public_key["n2"],
            )
            paillier_ciphertext_v = self.paillier_encryption.encrypt(
                self.public_key, integer(witness_record["v"])
            )
            paillier_ciphertext_open_v = self.paillier_encryption.encrypt(
                self.public_key,
                integer(SHA256(bytes(str(witness_record["openv"]), "utf-8"))),
            )
            paillier_ciphertexts.append(
                {
                    "i": witness_record["i"],
                    "pencv": paillier_ciphertext_v,
                    "penco": paillier_ciphertext_open_v,
                }
            )
            paillier_ciphertext_random_open_v = (
                self.paillier_encryption.encrypt(
                    self.public_key,
                    integer(SHA256(bytes(str(random_opening_v), "utf-8"))),
                )
            )
            paillier_ciphertext_random_v = self.paillier_encryption.encrypt(
                self.public_key, integer(SHA256(bytes(str(random_v), "utf-8")))
            )
            random_paillier_ciphertexts.append(
                {
                    "i": witness_record["i"],
                    "pencv": paillier_ciphertext_random_v,
                    "penco": paillier_ciphertext_random_open_v,
                }
            )

            s_v = random_v + (c * witness_record["v"])
            s_o_v = random_opening_v + (c * witness_record["openv"])
            if not (
                (
                    self.get_record_by_index(t_list, witness_record["i"])["e"]
                    * (
                        self.get_record_by_index(y_list, witness_record["i"])[
                            "e"
                        ]
                    )
                    ** c
                )
                == ((pair(ped_g, gt) ** s_v) * (pair(ped_h, gt) ** s_o_v))
            ):
                print("Abort: (FZK_PR) PPE Check failed.")
                exit()
            s_ppe = s_ppe * pair(g, gt) ** (s_v)
            #    integer_commitment_record = self.get_record_by_index(integer_commitments, witness_record["i"])
            #    randinteger_commitment_record = self.get_record_by_index(random_integer_commitments, witness_record["i"])
            hash_random_v = integer(SHA256(bytes(str(random_v), "utf-8")))
            hash_random_open_v = integer(
                SHA256(bytes(str(random_opening_v), "utf-8"))
            )
            v = integer(witness_record["v"])
            open_v = integer(
                SHA256(bytes(str(witness_record["openv"]), "utf-8"))
            )
            if not (
                integer_commitment_random_v[0]
                * (integer_commitment_v[0] ** hash_c)
                == (
                    (
                        (par_ic["g"] ** (hash_random_v + (hash_c * v)))
                        * (
                            par_ic["h"]
                            ** (
                                integer_commitment_random_v[1]
                                + (hash_c * integer_commitment_v[1])
                            )
                        )
                    )
                    % integer_commitment.n
                )
            ):
                print("Abort: (FZK_PR) Integer commitment check failed.")
            if not (
                integer_commitment_random_open_v[0]
                * (integer_commitment_open_v[0] ** hash_c)
                == (
                    (
                        (
                            par_ic["g"]
                            ** (hash_random_open_v + (hash_c * open_v))
                        )
                        * (
                            par_ic["h"]
                            ** (
                                integer_commitment_random_open_v[1]
                                + (hash_c * integer_commitment_open_v[1])
                            )
                        )
                    )
                    % integer_commitment.n
                )
            ):
                print("Abort: (FZK_PR) Integer commitment check failed.")
            c_t = {
                "c": paillier_ciphertext_random_v[0]["c"]
                * (paillier_ciphertext_v[0]["c"] ** hash_c)
            }
            if not (c_t["c"] % paillier_n_2) == (
                (
                    (
                        (paillier_g % paillier_n_2)
                        ** (hash_random_v + (hash_c * v))
                    )
                    * (
                        (
                            paillier_ciphertext_random_v[1]
                            * (paillier_ciphertext_v[1] ** hash_c)
                            % paillier_n_2
                        )
                        ** paillier_n
                    )
                )
                % paillier_n_2
            ):
                print(
                    "Abort: (FZK_PR) Paillier ciphertext verification failed."
                )
                exit()
            c_t = {
                "c": paillier_ciphertext_random_open_v[0]["c"]
                * (paillier_ciphertext_open_v[0]["c"] ** hash_c)
            }
            if not (c_t["c"] % paillier_n_2) == (
                (
                    (
                        (paillier_g % paillier_n_2)
                        ** (hash_random_open_v + (hash_c * open_v))
                    )
                    * (
                        (
                            paillier_ciphertext_random_open_v[1]
                            * (paillier_ciphertext_open_v[1] ** hash_c)
                            % paillier_n_2
                        )
                        ** paillier_n
                    )
                )
                % paillier_n_2
            ):
                print(
                    "Abort: (FZK_PR) Paillier ciphertext verification failed."
                )
                exit()

            ppe = ppe * pair(g, gt) ** random_v
            random_witnesses.append(
                {
                    "i": witness_record["i"],
                    "rv": random_v,
                    "ro": random_opening_v,
                }
            )

        y_result = pair(g ** result, gt)
        t_result = ppe
        hash_y = SHA256(
            (str(y_list) + str(integer_commitments) + str(t_list)).encode(
                "utf-8"
            )
        )
        dsa_a = dsa.generate_random()
        dsa_b = dsa.generate_random()
        g_d = dsa_keys[0]["g"] ** dsa_a
        tag = (
            dsa_keys[0]["g"] ** integer(SHA256(str(sid).encode("utf-8")))
        ) * (dsa_keys[0]["y"] ** g_d)
        dsa_c = (g_d ** dsa_b) * (tag ** integer(hash_y))
        if not ((t_result * (y_result ** c)) == (s_ppe)):
            print("Abort: (FZK_PR) PPE check failed.")
            exit()
        hash_m = SHA256(
            (str(y_list) + str(integer_commitments) + str(t_list)).encode(
                "utf-8"
            )
        )
        dsa_h = (
            dsa_keys[0]["g"] ** integer(SHA256(str(sid).encode("utf-8")))
        ) * (dsa_keys[0]["y"] ** g_d)
        if not (((g_d ** dsa_b) * (dsa_h ** integer(hash_m))) == (dsa_c)):
            print("Abort: (FZK_PR) DSA check failed.")
            exit()
        ped_g = par_c["g"]
        ped_h = par_c["h"]
        for witness_record in witness_pr:
            open_i = witness_record["openi"]
            com_i = self.get_record_by_index(instance_pr, witness_record["i"])[
                "comi"
            ]

            # Verifier picks x rand
            x = group.random(ZR)
            y = ped_h ** x

            u_list = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

            a_i = [
                self.sign_u(0, ped_g, x),
                self.sign_u(1, ped_g, x),
                self.sign_u(2, ped_g, x),
                self.sign_u(3, ped_g, x),
                self.sign_u(4, ped_g, x),
                self.sign_u(5, ped_g, x),
                self.sign_u(6, ped_g, x),
                self.sign_u(7, ped_g, x),
                self.sign_u(8, ped_g, x),
                self.sign_u(9, ped_g, x),
            ]
            str_num = self.num_to_str((witness_record["i"] - end) + 1000, 4)
            # ul = 1000?
            # Verifier picks vj rand
            v_0 = group.random(ZR)
            v_1 = group.random(ZR)
            v_2 = group.random(ZR)
            v_3 = group.random(ZR)

            v_j = [
                a_i[int(str_num[3])] ** v_0,
                a_i[int(str_num[2])] ** v_1,
                a_i[int(str_num[1])] ** v_2,
                a_i[int(str_num[0])] ** v_3,
            ]
            # v_j = [a_i[0]**v0,a_i[0]**v1,a_i[1]**v2,a_i[0]**v3]
            # Prover
            s_0 = group.random(ZR)
            t_0 = group.random(ZR)
            m_0 = group.random(ZR)

            s_1 = group.random(ZR)
            t_1 = group.random(ZR)
            m_1 = group.random(ZR)

            s_2 = group.random(ZR)
            t_2 = group.random(ZR)
            m_2 = group.random(ZR)

            s_3 = group.random(ZR)
            t_3 = group.random(ZR)
            m_3 = group.random(ZR)

            gt = group.random(G2)

            a_0 = (pair(v_j[0], gt) ** (-s_0)) * (pair(ped_g, gt) ** t_0)
            a_1 = (pair(v_j[1], gt) ** (-s_1)) * (pair(ped_g, gt) ** t_1)
            a_2 = (pair(v_j[2], gt) ** (-s_2)) * (pair(ped_g, gt) ** t_2)
            a_3 = (pair(v_j[3], gt) ** (-s_3)) * (pair(ped_g, gt) ** t_3)

            d = (
                ((ped_g ** ((10 ** 0) * s_0)) * (ped_h ** m_0))
                * ((ped_g ** ((10 ** 1) * s_1)) * (ped_h ** m_1))
                * ((ped_g ** ((10 ** 2) * s_2)) * (ped_h ** m_2))
                * ((ped_g ** ((10 ** 3) * s_3)) * (ped_h ** m_3))
            )

            # Ver
            c = group.random(ZR)

            # Prov
            z_s_0 = s_0 - (int(str_num[3]) * c)
            z_v_0 = t_0 - (v_0 * c)
            z_r_0 = m_0 - (open_i * c)

            z_s_1 = s_1 - (int(str_num[2]) * c)
            z_v_1 = t_1 - (v_1 * c)
            z_r_1 = m_1 - (open_i * c)

            z_s_2 = s_2 - (int(str_num[1]) * c)
            z_v_2 = t_2 - (v_2 * c)
            z_r_2 = m_2 - (open_i * c)

            z_s_3 = s_3 - (int(str_num[0]) * c)
            z_v_3 = t_3 - (v_3 * c)
            z_r_3 = m_3 - (open_i * c)
            y = gt ** x
            z_r = (m_0 + m_1 + m_2 + m_3) - (open_i * c)
            if not (
                a_0
                == (pair(v_j[0], y) ** c)
                * (pair(v_j[0], gt) ** -z_s_0)
                * (pair(ped_g, gt) ** z_v_0)
            ):
                print("Abort: (FZK_PR) A0 check failed.")
            if not (
                a_1
                == (pair(v_j[1], y) ** c)
                * (pair(v_j[1], gt) ** -z_s_1)
                * (pair(ped_g, gt) ** z_v_1)
            ):
                print("Abort: (FZK_PR) A1 check failed.")
            if not (
                a_2
                == (pair(v_j[2], y) ** c)
                * (pair(v_j[2], gt) ** -z_s_2)
                * (pair(ped_g, gt) ** z_v_2)
            ):
                print("Abort: (FZK_PR) A2 check failed.")
            if not (
                a_3
                == (pair(v_j[3], y) ** c)
                * (pair(v_j[3], gt) ** -z_s_3)
                * (pair(ped_g, gt) ** z_v_3)
            ):
                print("Abort: (FZK_PR) A3 check failed.")
            if not (
                d
                == (com_i ** c)
                * (~(ped_g ** ((end - 1000) * c)))
                * (ped_h ** (z_r))
                * ((ped_g ** ((10 ** 0) * z_s_0)))
                * ((ped_g ** ((10 ** 1) * z_s_1)))
                * ((ped_g ** ((10 ** 2) * z_s_2)))
                * ((ped_g ** ((10 ** 3) * z_s_3)))
            ):
                print("Abort: (FZK_PR) D check failed.")
            # Verifier picks x rand
            x = group.random(ZR)
            y = ped_h ** x
            u_list = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
            a_i = [
                self.sign_u(0, ped_g, x),
                self.sign_u(1, ped_g, x),
                self.sign_u(2, ped_g, x),
                self.sign_u(3, ped_g, x),
                self.sign_u(4, ped_g, x),
                self.sign_u(5, ped_g, x),
                self.sign_u(6, ped_g, x),
                self.sign_u(7, ped_g, x),
                self.sign_u(8, ped_g, x),
                self.sign_u(9, ped_g, x),
            ]
            # print('RSig size: '+str(sys.getsizeof(a_i)))
            str_num = self.num_to_str(
                (witness_record["i"] - start), 4
            )  # ul = 1000?
            # Verifier picks vj rand
            v_0 = group.random(ZR)
            v_1 = group.random(ZR)
            v_2 = group.random(ZR)
            v_3 = group.random(ZR)
            v_j = [
                a_i[int(str_num[3])] ** v_0,
                a_i[int(str_num[2])] ** v_1,
                a_i[int(str_num[1])] ** v_2,
                a_i[int(str_num[0])] ** v_3,
            ]
            # v_j = [a_i[0]**v0,a_i[0]**v1,a_i[1]**v2,a_i[0]**v3]
            # Prover
            s_0 = group.random(ZR)
            t_0 = group.random(ZR)
            m_0 = group.random(ZR)

            s_1 = group.random(ZR)
            t_1 = group.random(ZR)
            m_1 = group.random(ZR)

            s_2 = group.random(ZR)
            t_2 = group.random(ZR)
            m_2 = group.random(ZR)

            s_3 = group.random(ZR)
            t_3 = group.random(ZR)
            m_3 = group.random(ZR)

            gt = group.random(G2)

            a_0 = (pair(v_j[0], gt) ** (-s_0)) * (pair(ped_g, gt) ** t_0)
            a_1 = (pair(v_j[1], gt) ** (-s_1)) * (pair(ped_g, gt) ** t_1)
            a_2 = (pair(v_j[2], gt) ** (-s_2)) * (pair(ped_g, gt) ** t_2)
            a_3 = (pair(v_j[3], gt) ** (-s_3)) * (pair(ped_g, gt) ** t_3)

            d = (
                ((ped_g ** ((10 ** 0) * s_0)) * (ped_h ** m_0))
                * ((ped_g ** ((10 ** 1) * s_1)) * (ped_h ** m_1))
                * ((ped_g ** ((10 ** 2) * s_2)) * (ped_h ** m_2))
                * ((ped_g ** ((10 ** 3) * s_3)) * (ped_h ** m_3))
            )

            # Ver
            c = group.random(ZR)

            # Prov
            z_s_0 = s_0 - (int(str_num[3]) * c)
            z_v_0 = t_0 - (v_0 * c)
            z_r_0 = m_0 - (open_i * c)
            z_s_1 = s_1 - (int(str_num[2]) * c)
            z_v_1 = t_1 - (v_1 * c)
            z_r_1 = m_1 - (open_i * c)
            z_s_2 = s_2 - (int(str_num[1]) * c)
            z_v_2 = t_2 - (v_2 * c)
            z_r_2 = m_2 - (open_i * c)
            z_s_3 = s_3 - (int(str_num[0]) * c)
            z_v_3 = t_3 - (v_3 * c)
            z_r_3 = m_3 - (open_i * c)
            y = gt ** x
            z_r = (m_0 + m_1 + m_2 + m_3) - (open_i * c)
            if not (
                a_0
                == (pair(v_j[0], y) ** c)
                * (pair(v_j[0], gt) ** -z_s_0)
                * (pair(ped_g, gt) ** z_v_0)
            ):
                print("Abort: (FZK_PR) A0 check failed.")
            if not (
                a_1
                == (pair(v_j[1], y) ** c)
                * (pair(v_j[1], gt) ** -z_s_1)
                * (pair(ped_g, gt) ** z_v_1)
            ):
                print("Abort: (FZK_PR) A1 check failed.")
            if not (
                a_2
                == (pair(v_j[2], y) ** c)
                * (pair(v_j[2], gt) ** -z_s_2)
                * (pair(ped_g, gt) ** z_v_2)
            ):
                print("Abort: (FZK_PR) A2 check failed.")
            if not (
                a_3
                == (pair(v_j[3], y) ** c)
                * (pair(v_j[3], gt) ** -z_s_3)
                * (pair(ped_g, gt) ** z_v_3)
            ):
                print("Abort: (FZK_PR) A3 check failed.")
            if not (
                d
                == (com_i ** c)
                * (~(ped_g ** ((start) * c)))
                * (ped_h ** (z_r))
                * ((ped_g ** ((10 ** 0) * z_s_0)))
                * ((ped_g ** ((10 ** 1) * z_s_1)))
                * ((ped_g ** ((10 ** 2) * z_s_2)))
                * ((ped_g ** ((10 ** 3) * z_s_3)))
            ):
                print("Abort: (FZK_PR) D check failed.")
        self.f_nym.insert(sid, id, id)
        self.l_store.append({"sid": sid, "p": id, "Tk": id})
        return instance_pr, result


class FREG:
    def __init__(self):
        self.key = ""

    def register(self, key):
        self.key = key

    def retrieve(self):
        return self.key


class FCRS:
    def __init__(self):
        self.par = ""
        self.par_c = ""

    def set(self, par, par_c):
        self.par = par
        self.par_c = par_c

    def get(self):
        return self.par, self.par_c
