/**
 \file 		dectree.cpp
 \author 	kiss@encrypto.cs.tu-darmstadt.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
		Copyright (C) 2019 Engineering Cryptographic Protocols Group, TU Darmstadt
		This program is free software: you can redistribute it and/or modify
            	it under the terms of the GNU Lesser General Public License as published
           	 by the Free Software Foundation, either version 3 of the License, or
            	(at your option) any later version.
            	ABY is distributed in the hope that it will be useful,
            	but WITHOUT ANY WARRANTY; without even the implied warranty of
            	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
            	GNU Lesser General Public License for more details.
            	You should have received a copy of the GNU Lesser General Public License
            	along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		Decision tree implementation
 */

#include "dectree.h"
/**
 * Node constructor that takes its number num, by default it has no children
 * and parents, is not colored.
 * @param num the number that identifies the node
 */
DecTree::Node::Node()
  : left(0)
  , right(0)
  , parent(0)
  , level(0)
  , leaf(false)
  , threshold(0)
  , attribute_index(0)
  , classification(0)
  {}

DecTree::Node::Node(const Node& other){
    left = new Node(*(other.left));
    right = new Node(*(other.right));
    parent = new Node(*(other.parent));
    level = other.level;
    leaf = other.leaf;
    threshold = other.threshold;
    attribute_index = other.attribute_index;
    classification = other.classification;
}

/**
 * Gamma2 constructor that creates a Gamma2 graph with specified number of Nodes
 * @param num the number specifying the number of Nodes
 */
DecTree::DecTree()
  {
    num_attributes = 0;
    num_dec_nodes = 0;
    depth = 0;
    num_of_leaves = 0;
    dummy_non_full = 0;
}

DecTree::DecTree(const DecTree& other){
    node_vec = other.node_vec;
    decnode_vec = other.decnode_vec;
    attributes = other.attributes;
    thresholds = other.thresholds;
    num_attributes = other.num_attributes;
    num_dec_nodes = other.num_dec_nodes;
    depth = other.depth;
    num_of_leaves = other.num_of_leaves;
    dummy_non_full = other.dummy_non_full;
}

/**
 * Add a node
 * @param node the Node to be added to the tree
 */
void DecTree::add_node(DecTree::Node* node){
    node_vec.push_back(node);
}

/**
 * Add a decision node
 * @param node the Node to be added to the tree
 */
void DecTree::add_decnode(DecTree::Node* node){
    decnode_vec.push_back(node);
}

/**
 * Add an edge between two nodes
 * @param n1 the starting Node of the edge
 * @param n2 the ending Node of the edge
 */
void DecTree::add_edge(DecTree::Node* n1, DecTree::Node* n2){
    n2->parent = n1;
    n2->level = n1->level + 1;
	if(n1->left == NULL){
        n1->left = n2;
	}
	else{
        n1->right = n2;
	}
}

/**
 * Takes a string in the Format "i i i ..." separated by ' '
 * @param str the string to tokenize
 * @param tokens the result vector of wire id
 */
void tokenize(const std::string& str, std::vector<string>& tokens) {
	tokens.clear();
	std::size_t prev = 0, pos;
    while ((pos = str.find_first_of(" []", prev)) != std::string::npos)
    {
        if (pos > prev)
            tokens.push_back(str.substr(prev, pos-prev));
        prev = pos+1;
    }
    if (prev < str.length())
        tokens.push_back(str.substr(prev, std::string::npos));
}

/**
 * Erase First Occurrence of given  substring from main string.
 */
void eraseSubStr(std::string & mainStr, const std::string & toErase)
{
	// Search for the substring in string
	size_t pos = mainStr.find(toErase);

	if (pos != std::string::npos)
	{
		// If found then erase it from string
		mainStr.erase(pos, toErase.length());
	}
}

class SearchFunction {
    public:
        SearchFunction(uint32_t item): item_(item) {}
        bool operator()(uint64_t const & ref) {
            return ref == item_;
        }
    private:
        uint32_t item_;
};

//root node will be in decnode_vec[0] and node_vec[0]
void DecTree::read_from_file(string string_file){
    const char* filename = string_file.c_str();
    ifstream file;
    file.open(filename);
    cout << "Reading from " << filename << endl;

    //ofstream file2;
    //file2.open("dectree.txt", std::ios_base::app);

    uint32_t node1;
    uint32_t node2;

    DecTree::Node* node;
    uint32_t index;
    string line;
    vector<string> tokens;
    vector<uint64_t>::iterator it;
    float thres;
    while (getline(file, line)){
        tokenize(line, tokens);
        if(tokens[1] == "label=\"gini"){
            node1 = atoi(tokens[0].c_str());
            this->add_node(new DecTree::Node());
            this->node_vec[node1]->leaf = true;
            this->num_of_leaves++;
            this->node_vec[node1]->classification = rand() % 100;
        }
        else if(tokens[1] == "label=\"X"){
            node1 = atoi(tokens[0].c_str());
            //cout << node1 << endl;
            node = new DecTree::Node();
            index = atoi(tokens[2].c_str());
            node->attribute_index = index;
            //cout << index << endl;
            string str_cleaned = tokens[4];
            eraseSubStr(str_cleaned, "\\ngini");
            thres = atof(str_cleaned.c_str());
            node->threshold = thres*1000;
            //cout << node->threshold << endl; //Thresholds are converted so that we only compare integers
            this->num_dec_nodes++;
            this->add_node(node);
            this->add_decnode(node);

            it = find_if(this->attributes.begin(), this->attributes.end(), SearchFunction(index));
            if(it == this->attributes.end()){
                this->num_attributes++;
            }
            this->attributes.push_back(index);
            this->thresholds.push_back(node->threshold);
        }
        else if(tokens[1] == "->"){
            node1 = atoi(tokens[0].c_str());
            node2 = atoi(tokens[2].c_str());
            this->add_edge(this->node_vec[node1], this->node_vec[node2]);
        }
    }
    for(uint32_t i = 0; i < this->node_vec.size(); ++i){
        node = this->node_vec[i];
        if(node->leaf){ //Right is also 0 in this case
	    if(node->level > this->depth){
                this->depth = node->level;
            }
        }
    }
    //cout << "Total number of attributes " << this->num_attributes << endl;
    //cout << "Depth of the tree " << this->depth << endl;
    //cout << "Total number of decision nodes " << this->num_dec_nodes << endl;
    //cout << "Total number of leaves " << this->num_of_leaves << endl;

    for(uint32_t i = 0; i < this->node_vec.size(); ++i){
        node = this->node_vec[i];
        if(node->leaf){
            this->dummy_non_full += this->depth - node->level;
        }
    }
    //cout << "Total number of dummy nodes in non-full tree " << this->dummy_non_full << endl;

    uint32_t total_number_of_edges = 0;
    for(uint32_t i = 0; i < this->node_vec.size(); ++i){
        node = this->node_vec[i];
        if(node->leaf){
            total_number_of_edges += node->level;
        }
    }
    //cout << "Total number of edges " << total_number_of_edges << endl;
    file.close();
    //file2.close();
}


void DecTree::fullTree(uint32_t num_att, uint32_t tree_depth){
    this->num_attributes = num_att;
    this->num_dec_nodes = pow(2.0, num_att);
    this->depth = tree_depth;
    this->num_of_leaves = pow(2.0, num_att + 1);
    vector<uint64_t> attr(num_att, 0);
    vector<uint64_t> thres(this->num_dec_nodes, 0);
    this->attributes = attr;
    this->thresholds = thres;

    for(uint32_t i = 0; i < this->num_dec_nodes + this->num_of_leaves; ++i){
        DecTree::Node* newNode = new DecTree::Node();
        if(i == 0){
            newNode->parent = NULL;
            newNode->level = 0;
        }
        else if(i%2 == 0){
            this->node_vec[i/2 - 1]->right = newNode;
            newNode->parent = this->node_vec[i/2 - 1];
            newNode->level = newNode->parent->level + 1;
        }
        else if(i%2 == 1){ //odd case
            this->node_vec[i/2]->left = newNode;
            newNode->parent = this->node_vec[i/2];
            newNode->level = newNode->parent->level + 1;
        }

        if(i < this->num_dec_nodes){
            this->decnode_vec.push_back(newNode);
        }
        else{
            newNode->leaf = true;
        }
        this->node_vec.push_back(newNode);
    }
}

void DecTree::depthPad(){
    DecTree::Node* tmp;
    for(uint32_t i = 0; i < this->node_vec.size(); ++i){
        if(this->node_vec[i]->leaf){
            if(this->node_vec[i]->level != this->depth){
                tmp = this->node_vec[i];
                this->node_vec[i] = new DecTree::Node();
                this->node_vec[i]->parent = tmp->parent;
                this->node_vec[i]->level = tmp->level; //leaf is false, threshold is 0, attribute_index is 0
                this->decnode_vec.push_back(this->node_vec[i]);
                this->attributes.push_back(this->node_vec[i]->attribute_index);
                this->thresholds.push_back(this->node_vec[i]->threshold);
                this->num_dec_nodes++;

                tmp->level++;
                tmp->parent = this->node_vec[i];
                this->node_vec[i]->left = tmp;
                this->node_vec[i]->right = tmp;
                this->node_vec.push_back(tmp);
            }
        }
    }
    //cout << "Number of decision nodes " << this->num_dec_nodes << endl;
}

void DecTree::evaluate(vector<uint64_t> inputs){
    DecTree::Node* this_node = this->node_vec[0];
    while(!(this_node->leaf)){
        //cout << inputs[this_node->attribute_index] << endl;
        //cout << this_node->threshold << endl;
        if(inputs[this_node->attribute_index] <= this_node->threshold){
            this_node = this_node->left;
        }
        else{
            this_node = this_node->right;
        }
    }
}

/**
 * Destructor DecTree
 */
DecTree::~DecTree(){
	node_vec.clear();
}
