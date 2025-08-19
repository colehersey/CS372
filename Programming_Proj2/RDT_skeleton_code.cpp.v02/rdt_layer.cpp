#pragma once

#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "segment.cpp"
#include "unreliable.cpp"

using std::cout;
using std::endl;
using std::optional;
using std::string;
using std::vector;

/**
 * RDTLayer
 * 
 * Description:
 *   The reliable data transfer (RDT) layer is used as a communication layer to resolve issues over an unreliable
 *   channel.
 * 
 * 
 * Notes:
 * This file is meant to be changed.
 * 
 * 
 **/
class RDTLayer{
    /**
     * Class Scope Variables
     * 
     * 
     * 
     **/
    //private by default, but I prefer being explicit!
    private:
        int DATA_LENGTH;            //The length of the string data that will be sent per packet in characters.
        int FLOW_CONTROL_WIN_SIZE;  //Receive window size for flow-control.

        /*Note: sendChannel and receiveChannel are set in the rdt_main...
                We are using the optional<UnreliableChannel> type to have behavior
                similar to using none that is then set to an object in Python.
                
                We could use pointers all over, but since we do not do any none or nullptr checking
                or do any pointer manipulation anyway...
        */
        optional<UnreliableChannel> sendChannel;
        optional<UnreliableChannel> receiveChannel;
        string dataToSend;
        int currentIteration;       //Use this for segment "timeouts"
        int countSegmentTimeouts; //use this to track how many segments actually timeout

        /************************************************************
         * Add items here as needed!                                *
         ************************************************************/

    public:
        RDTLayer(){
            this->dataToSend = "";
            this->currentIteration = 0;
            this->countSegmentTimeouts = 0;

            /************************************************************
             * Add items here as needed!                                *
             ************************************************************/
        }

        /**
         * setSendChannel()
         * 
         * Description:
         *   Called by main to set the unreliable sending lower-layer channel
         * 
         * 
         **/
        void setSendChannel(UnreliableChannel channel){
            this->sendChannel = channel;
        }

        /**
         * setReceiveChannel()
         * 
         * Description:
         *   Called by main to set the unreliable receiving lower-layer channel
         * 
         * 
         **/
        void setReceiveChannel(UnreliableChannel channel){
            this->receiveChannel = channel;
        }

        /**
         * setDataToSend()
         * 
         * Description:
         *   Called by main to set the string data to send
         * 
         * 
         **/
        void setDataToSend(string data){
            this->dataToSend = data;
        }

        /**
         * getDataReceived()
         * 
         * Description:
         *   Called by main to get the currently received and buffered string data, in order
         * 
         * 
         **/
        string getDataReceived(){
            /************************************************************
             * identify the data that has been received...              *
             *                                                          *
             * Add code to this function as needed!                     *
             ************************************************************/
            cout << "getDataReceived(): Complete this..." << endl;

            return "";
        }

        /* ************************************************************************************************************** */
        /* getCountSegmentTimeouts()                                                                                      */
        /*                                                                                                                */
        /* Description:                                                                                                   */
        /* Called by main to get the count of segment timeouts                                                            */
        /*                                                                                                                */
        /*                                                                                                                */
        /* ************************************************************************************************************** */
        int getCountSegmentTimeouts()
        {
            return this->countSegmentTimeouts;
        }

        /**
         * processData()
         * 
         * Description:
         *   "timeslice". Called by main once per iteration
         * 
         * 
         **/
        void processData(){
            this->currentIteration++;
            this->processSend();
            this->processReceiveAndSendResponse();
        }

        /**
         * processSend()
         * 
         * Description:
         *   Manages Segment sending tasks
         * 
         * 
         **/
        void processSend(){
            Segment segmentSend;
            
            /**************************************************/
            cout << "processSend(): Complete this..." << endl;
            /************************************************************
             * Add code to this function as needed!
             * 
             * You should pipeline segments to fit the flow-control window
             * The flow-control window is the constant RDTLayer.FLOW_CONTROL_WIN_SIZE
             * The maximum data that you can send in a segment is RDTLayer.DATA_LENGTH
             * These constants are given in # characters
             * 
             * Somewhere in here you will be creating data segments to send.
             * The data is just part of the entire string that you are trying to send.
             * The seqnum is the sequence number for the segment (in character number, not bytes)
             ************************************************************/

            int seqnum = 0;
            string data = "x";

            /**************************************************/
            // Display sending segment
            segmentSend.setData(seqnum, data);
            cout << "Sending segment: " << segmentSend.to_string() << endl;

            //use the unreliable sendChannel to send the segment
            this->sendChannel->send(segmentSend);
        }

        /**
        * processReceiveAndSendResponse()
        * 
        * Description:
        *   Manages Segment receive tasks
        * 
        * 
        **/
        void processReceiveAndSendResponse(){
            Segment segmentAck; // Segment acknowledging packet(s) received

            //This call returns a list of incoming segments (see Segment class)...
            vector<Segment> listIncommingSegments = receiveChannel->receive();

            /*************************************************
             * What segments have been received?
             * How will you get them back in order?
             * This is where a majority of your logic will be implemented
             *************************************************/
            cout << "processReceiveAndSendResponse(): Complete this..." << endl;



            /*************************************************
             * How do you respond to what you have received?
             * How can you tell data segments apart from ack segments?
             *************************************************/
            cout << "processReceiveAndSendResponse(): Complete this..." << endl;

            /*************************************************
             * Somewhere in here you will be setting the contents of the ack segments to send.
             * The goal is to employ cumulative ack, just like TCP does...
             *************************************************/
            int acknum = 0;

            /*************************************************/
            // Display response segment
            segmentAck.setAck(acknum);
            cout << "Sending ack: " << segmentAck.to_string() << endl;

            // Use the Unreliable sendChannel to send the ack packet
            this->sendChannel->send(segmentAck);
        }
};
