// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.
import React, {useState, useRef, useMemo} from 'react'
import SimpleMDE from 'react-simplemde-editor'

import {Utils} from '../utils'
import './markdownEditor.scss'

type Props = {
    id?: string
    text?: string
    placeholderText?: string
    className?: string
    readonly?: boolean

    onChange?: (text: string) => void
    onFocus?: () => void
    onBlur?: (text: string) => void
    onAccept?: (text: string) => void
}

const MarkdownEditor = (props: Props): JSX. Element => {
    const {placeholderText, onFocus, onBlur, onChange, text, id} = props
    const [isEditing, setIsEditing] = useState(false)
    const [uniqueId] = useState(id || Utils.createGuid())

    const [active, setActive] = useState(false)
    const [editorInstance, setEditorInstance] = useState<any>()
    const editorOptions = useMemo(() => ({
        autoDownloadFontAwesome: true,
        toolbar: false,
        status: false,
        autofocus: true,
        spellChecker: true,
        nativeSpellcheck: true,
        minHeight: '10px',
        shortcuts: {
            toggleStrikethrough: 'Cmd-.',
            togglePreview: null,
            drawImage: null,
            drawLink: null,
            toggleSideBySide: null,
            toggleFullScreen: null,
        },
    }), [])

    const showEditor = (): void => {
        const cm = editorInstance?.codemirror
        if (cm) {
            setTimeout(() => {
                cm.refresh()
                cm.focus()
                cm.getInputField()?.focus()
                cm.setCursor(cm.lineCount(), 0) // Put cursor at end
            }, 100)
        }

        setIsEditing(true)
    }

    const stateAndPropsValue = {
        isEditing,
        setIsEditing,
        setActive,
        onBlur,
        onChange,
        onFocus,
    }
    const stateAndPropsRef = useRef(stateAndPropsValue)
    stateAndPropsRef.current = stateAndPropsValue

    const editorEvents = useMemo(() => ({
        change: (instance: any) => {
            if (stateAndPropsRef.current.isEditing) {
                const newText = instance.getValue()
                stateAndPropsRef.current.onChange?.(newText)
            }
        },
        blur: (instance: any) => {
            const newText = instance.getValue()
            const oldText = text || ''
            if (newText !== oldText && stateAndPropsRef.current.onChange) {
                stateAndPropsRef.current.onChange(newText)
            }

            stateAndPropsRef.current.setActive(false)

            if (stateAndPropsRef.current.onBlur) {
                stateAndPropsRef.current.onBlur(newText)
            }

            stateAndPropsRef.current.setIsEditing(false)
        },
        focus: () => {
            stateAndPropsRef.current.setActive(true)
            stateAndPropsRef.current.setIsEditing(true)

            if (stateAndPropsRef.current.onFocus) {
                stateAndPropsRef.current.onFocus()
            }
        },
    }), [])

    const html: string = Utils.htmlFromMarkdown(text || placeholderText || '')

    const previewElement = (
        <div
            className={text ? 'octo-editor-preview' : 'octo-editor-preview octo-placeholder'}
            style={{display: isEditing ? 'none' : undefined}}
            dangerouslySetInnerHTML={{__html: html}}
            onClick={() => {
                if (!props.readonly && !isEditing) {
                    showEditor()
                }
            }}
        />)

    const editorElement = (
        <div
            className='octo-editor-active Editor'

            // Use visibility instead of display here so the editor is pre-rendered, avoiding a flash on showEditor
            style={isEditing ? {} : {visibility: 'hidden', position: 'absolute', top: 0, left: 0}}
            onKeyDown={(e) => {
                // HACKHACK: Need to handle here instad of in CodeMirror because that breaks auto-lists
                if (e.keyCode === 27 && !e.shiftKey && !(e.ctrlKey || e.metaKey) && !e.altKey) { // Esc
                    editorInstance?.codemirror?.getInputField()?.blur()
                } else if (e.keyCode === 13 && !e.shiftKey && (e.ctrlKey || e.metaKey) && !e.altKey) { // Cmd+Enter
                    editorInstance?.codemirror?.getInputField()?.blur()

                    // HACKHACK: Call onAccept after visual state change
                    setTimeout(() => {
                        Utils.log('onAccept')
                        props.onAccept?.(text || '')
                    }, 20)
                }
            }}
        >
            <SimpleMDE
                id={uniqueId}
                getMdeInstance={setEditorInstance}
                value={text}
                events={editorEvents}
                options={editorOptions}
            />
        </div>)

    const element = (
        <div className={`MarkdownEditor octo-editor ${props.className || ''} ${active ? 'active' : ''}`}>
            {previewElement}
            {editorElement}
        </div>)

    return element
}

export {MarkdownEditor}
