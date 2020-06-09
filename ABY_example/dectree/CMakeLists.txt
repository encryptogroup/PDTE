
add_executable(decision_tree_test decision_tree_test.cpp common/dectree.cpp common/decision-tree-circuit.cpp common/auxiliary-functions.cpp common/sndrcv.cpp common/selection-functions.cpp common/crypto_party/dgk_party.cpp common/crypto_party/paillier_party.cpp common/crypto_party/paillier.cpp common/selection_blocks/e_SelectionBlock.cpp common/selection_blocks/t_SelectionBlock.cpp common/selection_blocks/permutation_network.cpp)
target_link_libraries(decision_tree_test ABY::aby ENCRYPTO_utils::encrypto_utils)
